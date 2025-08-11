package main

import (
	"flag"
	"log"
	"sync"
	"sync/atomic"
	"crypto/tls"
	"time"
	"net"
	"io/ioutil"
	"os"
)

var (
	connections     int
	interval	int
	address         string
	sni       	string
	conn_type       string
	debug		int
)

var conn_errors int64

func init() {
	flag.StringVar(&address, "address", ":443", "Server address")
	flag.StringVar(&sni, "sni", "localhost", "TLS SNI")
	flag.StringVar(&conn_type, "conn_type", "tcp", "Connection type")
	flag.IntVar(&connections, "connections", 1, "Number of connections to start")
	flag.IntVar(&interval, "interval", 0, "Interval to place connections in slot")
	flag.IntVar(&debug, "debug", 0, "Debug level")
	flag.Parse()
}

func my_sleep(delta int64) {
	var i int64 = 0

	if delta <= 0 {
		return
	}

	for i = 0; i < delta; i++ {
		time.Sleep(1 * time.Millisecond)
	}
}

func main() {
	log.SetOutput(os.Stdout)
	log.Printf("Starting %d parallel connections", connections)

	var t = time.Now().UnixMilli()
	var wg sync.WaitGroup
	for i := 1; i <= connections; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			connection(i)
		}(i)
		if (interval != 0) && (i % interval == 0) {
			wg.Wait()
			var new_t = time.Now().UnixMilli()
			my_sleep(125 - (new_t - t))
			t = new_t
		}
	}
	wg.Wait()

	log.Printf("Finished: %d Errors: %d", connections, conn_errors)
}

func connection(cid int) {
	d := net.Dialer{Timeout: 2 * time.Second}
	var err error
	var conn net.Conn

	if conn_type == "tcp" {
		conn, err = d.Dial("tcp", address)
	} else if conn_type == "tls" {
		conf := &tls.Config{
			InsecureSkipVerify: true,
		}
		conn, err = tls.DialWithDialer(&d, "tcp", address, conf)
	} else {
		panic("Unknown connection type")
	}

	if err != nil {
		//TLS connection may reach this branch
		atomic.AddInt64(&conn_errors, 1)
		return
	}

	/* Let RST to be received */
	time.Sleep(time.Duration(125) * time.Millisecond)

	second := time.Millisecond * time.Duration(10)
	conn.SetReadDeadline(time.Now().Local().Add(second))
	_, err = ioutil.ReadAll(conn)

	if err != nil {
		if !os.IsTimeout(err) {
			atomic.AddInt64(&conn_errors, 1)
			if debug > 0 {
				log.Printf("Error: %s", err)
			}
			conn.Close()
		}
	}
}
