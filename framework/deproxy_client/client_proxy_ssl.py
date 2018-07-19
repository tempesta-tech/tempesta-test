#!/usr/bin/python3

import getopt
import sys
import io
import os
import time
import ssl

import signal
import socket
import http.server

sock = None
sslsock = None
rootCA = None

listen = 7000
cafile = None

def set_ca(ca):
    global rootCA
    rootCA = ca
    caf = open(cafile, 'w')
    caf.write(ca.decode("utf-8"))
    caf.close()
    print("Certificate loaded\n")

def connect(addr, port, server_hostname):
    global sock
    global sslsock
    if sock != None:
        raise Exception("already connected")
    sock = socket.socket()
    sock.connect((addr, int(port)), )
    try:
        if cafile != None:
            sslsock = ssl.wrap_socket(sock, ca_certs=cafile, cert_reqs=ssl.CERT_REQUIRED)
        else:
            sslsock = ssl.wrap_socket(sock)
        sslsock.setblocking(False)
    except Exception as e:
        sock.close()
        sock = None
        sslsock = None
        raise e

def request(content):
    global sslsock
    if sslsock is None:
        raise Exception("socket is closed")
    sslsock.send(content)

def read_response(maxlen):
    global sslsock
    if sslsock is None:
        raise Exception("socket is closed")
    try:
        ans = sslsock.recv(int(maxlen))
    except io.BlockingIOError:
        return b""
    except ssl.SSLWantReadError:
        return b""
    return ans

def finish():
    global sock
    global sslsock
    if sock is None:
        raise Exception("socket is closed")
    sslsock.close()
    sslsock = None
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
            if command == 'set_ca':
                cl = self.headers.get('content-length')
                if cl is None:
                    raise Exception("No content-length header is specified")
                content_len = int(cl)
                ca = self.rfile.read(content_len)
                set_ca(ca)
                self.send_response(200)
                self.send_header('Result', 'ok')
                self.end_headers()
            elif command == 'connect':
                addr = self.headers.get('addr')
                port = self.headers.get('port')
                host = self.headers.get('server_hostname')
                if addr is None:
                    raise Exception("No addr header is specified")
                if port is None:
                    raise Exception("No port header is specified")
                if host is None:
                    host = addr
                connect(addr, port, host)
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
        sys.stdout.flush()
        sys.stderr.flush()

daemon = True

try:
    options, remainder = getopt.getopt(sys.argv[1:], 'l:d',
                                       ['listen=', 'no-daemonize'])

    for opt, arg in options:
        if opt in ('-l', '--listen'):
            listen = int(arg)
        if opt in ('-d', '--no-daemonize'):
            daemon = False

except getopt.GetoptError as e:
    print(e)
    sys.exit(2)
except Exception as e:
    print(e)
    sys.exit(2)

pidfile = 'proxy-%i.pid' % listen
logfile = 'proxy-%i.log' % listen
cafile  = 'rootCA-%i.crt' % listen

def wait_for_pidfile(timeout=2):
    t0 = time.time()
    while not os.path.exists(pidfile):
        t = time.time()
        if t - t0 > timeout:
            return

def fork(wait=True):
    try:
        pid = os.fork()
        if pid > 0:
            if wait:
                wait_for_pidfile(1)
            # wait while listen() starts
            time.sleep(0.5)
            sys.exit(0)
    except OSError as e:
        sys.stderr.write("Fork failed: %d (%s)\n" % (e.errno, e.strerror))
        sys.exit(1)

def clean():
    print("Exiting\n")
    sys.stdout.flush()
    os.remove(pidfile)
    if os.path.exists(cafile):
        os.remove(cafile)

def exit_handler(signal, frame):
    clean()
    sys.exit(0)


def test_pid_file(name):
    if not os.path.exists(name):
        return
    pidf = open(name, 'r')
    p = pidf.read()
    pidf.close()
    pid = None
    try:
        pid = int(p)
        os.kill(pid, 0)
    except:
        return
    print("Process %s,%s already exists\n" % (name, pid))
    sys.exit(3)

def daemonize():
    fork(True)

    os.setsid()
    os.umask(0)

    fork(False)

    sys.stdout.flush()
    sys.stderr.flush()

    stdin = open('/dev/null', 'r')
    os.dup2(stdin.fileno(), sys.stdin.fileno())

    stdout = open(logfile, 'w')
    os.dup2(stdout.fileno(), sys.stdout.fileno())
    os.dup2(stdout.fileno(), sys.stderr.fileno())

    pid = str(os.getpid())

    pidf = open(pidfile,'w+')
    pidf.write("%s\n" % pid)
    pidf.close()

    signal.signal(signal.SIGINT, exit_handler)
    signal.signal(signal.SIGTERM, exit_handler)

test_pid_file(pidfile)

if daemon:
    daemonize()
    print("Daemonized\n")
    sys.stdout.flush()

try:
    server_address = ('', listen)
    httpd = http.server.HTTPServer(server_address, DeproxyHandler)
    httpd.serve_forever()
except Exception as e:
    print("Error: %s\n" % e)
    clean()
    sys.exit(3)
