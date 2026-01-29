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
	flag.IntVar(&debug, "debug", 0, "Debug level")
	flag.Parse()
}

func main() {
	log.SetOutput(os.Stdout)
	log.Printf("Starting %d parallel connections", connections)

	var wg sync.WaitGroup
	for i := 0; i < connections; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			connection(i)
		}(i)
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
	time.Sleep(time.Duration(1) * time.Second)

	second := time.Second * time.Duration(1)
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
