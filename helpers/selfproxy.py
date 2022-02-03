"""
Built-in chunking proxy.

The SelfProxy class and it's companion classes are
used to divide TLS TCP stream into chunks when both
TLS connections and chunking testing are requested.

It works as an buil-in TCP proxy and supports
client proxy mode for deproxy.Client and server
proxy mode, however the later seems to be not
in demand.

The deproxy.Client should activate the proxy
with request_client_selfproxy() function and
release it with release_client_selfproxy()
function (see below).

TODO: with transition to Python 3 this class is
expected to be replaced with Python 3 solution
based on SSLObject class.
"""

import sys
import socket
import asyncore
import time
from . import error

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

CLIENT_MODE = 1
SERVER_MODE = 2

SERVER_PORT_REPLACE = 9000
CLIENT_PORT_REPLACE = 9001

MAX_MESSAGE_SIZE = 65536

#debugging
PXCONN_ACCEPTED  = 1
PXCONN_FORWARDED = 2

class ProxyConnection(asyncore.dispatcher_with_send):
    """
        This class represents a proxy TCP connection, both
        accepted one and forwarded one
    """
    def __init__(self, sock=None, pair=None, mode=PXCONN_ACCEPTED):
        asyncore.dispatcher_with_send.__init__(self, sock)
        self.pair = pair;
        self.closing = False
        self.segment_size = 0
        self.segment_gap = 0
        self.last_segment_time = 0
        #debug
        self.mode = mode

    #debug
    def modestr(self):
        return ( "FORWARDED" if self.mode == PXCONN_FORWARDED else
                 "ACCEPTED" if self.mode == PXCONN_ACCEPTED else
                 "" )

    def set_chunking(self, segment_size, segment_gap):
        self.segment_size = segment_size
        self.segment_gap = segment_gap

    def handle_connect(self):
        print (self.modestr() + ": handle_connect " + str(self.connected))
        pass

    def handle_error(self):
        _, v, _ = sys.exc_info()
        print (self.modestr() + ": handle_error " + str(v))
        pass

    def initiate_send(self):
        num_sent = 0
        num_sent = asyncore.dispatcher.send(self, self.out_buffer[:
                          self.segment_size
                          if self.segment_size > 0
                          else 4096 ])
        self.out_buffer = self.out_buffer[num_sent:]
        self.last_segment_time = time.time()
        if len(self.out_buffer) == 0 and self.closing:
            self.handle_close()

    def in_pause(self):
        return ( self.segment_gap != 0 and
                 time.time() - self.last_segment_time
                     < self.segment_gap / 1000.0 )

    def writable(self):
        #print("writable? " + str(self.in_pause()) + str(asyncore.dispatcher_with_send.writable(self)))
        if self.in_pause():
            return False;
        if self.closing:
            return True;
        return asyncore.dispatcher_with_send.writable(self)

    def send(self, data):
        print (self.modestr() + ": send")
        self.out_buffer = self.out_buffer + data
        if not self.in_pause():
            self.initiate_send()

    def readable(self):
        return self.pair.connected

    def handle_read(self):
        print (self.modestr() + ": handle_read")
        self.pair.send(self.recv(MAX_MESSAGE_SIZE))

    def handle_close(self):
        print (self.modestr() + ": handle_close")
        self.ready = False
        self.closing = True
        self.pair.closing = True
        self.close()

    #debug
    def handle_write(self):
        print (self.modestr() + ": handle_write")
        asyncore.dispatcher_with_send.handle_write(self)

class SelfProxy(asyncore.dispatcher):

    def __init__(self, mode, listen_host, listen_port,
                       forward_host, forward_port,
                       segment_size, segment_gap):
        asyncore.dispatcher.__init__(self)
        self.mode = mode
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.forward_host = forward_host
        self.forward_port = forward_port
        self.segment_size = segment_size
        self.segment_gap = segment_gap
        self.connections = []

        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((self.listen_host, self.listen_port))
        self.listen(socket.SOMAXCONN)

    def handle_close(self):
        self.close()
        for conn in self.connections:
            if conn.connected:
                conn.handle_close()

    def stop(self):
        self.handle_close()

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            print("Accepted")
            sock, _ = pair
            accepted_conn = ProxyConnection(sock=sock,mode=PXCONN_ACCEPTED)
            forward_conn = ProxyConnection(pair=accepted_conn,mode=PXCONN_FORWARDED)
            accepted_conn.pair = forward_conn
            accepted_conn.ready = True
            if self.mode == CLIENT_MODE:
                forward_conn.set_chunking(self.segment_size, self.segment_gap)
            elif self.mode == SERVER_MODE:
                accepted_conn.set_chunking(self.segment_size, self.segment_gap)
            else:
                error.bug("Invalid SelfProxy mode")
            forward_conn.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            forward_conn.bind((self.listen_host, 0))
            forward_conn.connect((self.forward_host, self.forward_port))
            self.connections.append(accepted_conn)
            self.connections.append(forward_conn)

client_selfproxy = None
client_selfproxy_count = 0

"""
The request_client_selfproxy() function create the client mode SelfProxy.
The single SelfProxy instance is used for all client connections.
The instance is use-counted, so any client which reqiests the
SelfProxy must then releas it with release_client_selfproxy() function.

The parameters of the function are transferred into instance constructor.

IMPORTANT LIMITATION:
It is assumed currently that all client connections will be directed
to the same server. So the parameters of the only first call influence
on SelfProxy instance, and the parameters of next calls are ignored
and only the use couner is incremented. This should be reworked if
meet some contardiction with future requirements.
"""
def request_client_selfproxy(listen_host, listen_port,
                       forward_host, forward_port,
                       segment_size, segment_gap):
    global client_selfproxy
    global client_selfproxy_count
    print "Request"
    if client_selfproxy is None:
        client_selfproxy = SelfProxy(CLIENT_MODE,
                           listen_host, listen_port,
                           forward_host, forward_port,
                           segment_size, segment_gap)
        client_selfproxy_count = 1
    else:
        client_selfproxy_count += 1

def release_client_selfproxy():
    global client_selfproxy
    global client_selfproxy_count
    print "Release"
    client_selfproxy_count -= 1
    if client_selfproxy_count <= 0:
        if client_selfproxy is not None:
            client_selfproxy.stop()
            client_selfproxy = None
        client_selfproxy_count = 0
