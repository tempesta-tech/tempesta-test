#!/usr/bin/python3

import getopt
import sys
import io

import socket
import http.server

sock = None

def connect(addr, port):
    global sock
    if sock != None:
        raise Exception("already connected")
    sock = socket.socket()
    sock.connect((addr, int(port)))
    sock.setblocking(False)

def request(content):
    global sock
    if sock is None:
        raise Exception("socket is closed")
    sock.send(content)

def read_response(maxlen):
    global sock
    if sock is None:
        raise Exception("socket is closed")
    try:
        ans = sock.recv(int(maxlen))
    except io.BlockingIOError:
        return b""
    return ans

def finish():
    global sock
    if sock is None:
        raise Exception("socket is closed")
    sock.close()
    sock = None

class DeproxyHandler(http.server.BaseHTTPRequestHandler):
    """ Handle commands from framework """
    def do_POST(self):
        try:
            command = self.headers.get('command')
            if command is None:
                self.send_response(400)
                self.send_header('Result', 'error')
                self.end_headers()
                self.wfile.write(b"No command specified\n")
                return

            if command == 'connect':
                addr = self.headers.get('addr')
                port = self.headers.get('port')
                if addr is None:
                    raise Exception("No addr header is specified")
                if port is None:
                    raise Exception("No port header is specified")
                connect(addr, port)
                self.send_response(200)
                self.send_header('Result', 'ok')
                self.end_headers()
            elif command == 'request':
                cl = self.headers.get('content-length')
                if cl is None:
                    raise Exception("No content-length header is specified")
                content_len = int(cl)
                content = self.rfile.read(content_len)
                request(content)
                self.send_response(200)
                self.send_header('Result', 'ok')
                self.end_headers()
                return
            elif command == 'read':
                maxlen = self.headers.get('maxlen')
                if maxlen is None:
                    raise Exception("No maxlen header is specified")
                data = read_response(maxlen)
                self.send_response(200)
                self.send_header('Result', 'ok')
                self.send_header('Content-Length', len(data))
                self.end_headers()
                self.wfile.write(data)
                return
            elif command == 'finish':
                finish()
                self.send_response(200)
                self.send_header('Result', 'ok')
                self.end_headers()
                return
            else:
                raise Exception("Unknown command %s" % command)
        except Exception as e:
            self.send_response(403)
            self.send_header('Result', 'error')
            self.end_headers()
            self.wfile.write(bytes("Error: %s\n" % str(e), "utf-8"))
            return

listen = 7000

try:
    options, remainder = getopt.getopt(sys.argv[1:], 'l:',
                                       ['listen='])

    for opt, arg in options:
        if opt in ('-l', '--listen'):
            listen = int(arg)

except getopt.GetoptError as e:
    print(e)
    sys.exit(2)
except Exception as e:
    print(e)
    sys.exit(2)


server_address = ('', listen)
httpd = http.server.HTTPServer(server_address, DeproxyHandler)
httpd.serve_forever()
