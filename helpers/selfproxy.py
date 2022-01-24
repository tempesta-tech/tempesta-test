"""
Built-in chunking proxy.

The SelfProxy class and it's companion classes are
used to divide TLS TCP stream into chunks when both
TLS connections and chunking testing are requested.

It works as an buil-in TCP proxy and supports
client proxy mode for deproxy.Client and server
proxy mode for deproxy.Server.

TODO: with transition to Python 3 this class is
expected to be replaced with Python 3 solution
based on SSLObject class.
"""

import asyncore
import time
from . import error

CLIENT_MODE = 1
SERVER_MODE = 2

SERVER_PORT_REPLACE = 90000
CLIENT_PORT_REPLACE = 90001

MAX_MESSAGE_SIZE = 65536

class ProxyConnection(asyncore.dispatcher_with_send):
    """
        This class represents a proxy TCP connection, both
        accepted one and forwarded one
    """
    def __init__(self, sock=None, pair=None):
        asyncore.dispatcher.__init__(self, sock)
        self.pair = pair;
        self.ready = False
        self.closing = False
        self.segment_size = 0
        self.segment_gap = 0
        self.last_segment_time = 0
        
    def set_chunking(segment_size, segment_gap):
        self.segment_size = segment_size
        self.segment_gap = segment_gap
            
    def handle_connect(self):
        self.ready = True
        
    def initiate_send(self):
        num_sent = 0
        num_sent = asyncore.dispatcher.send(self, self.out_buffer[:
                          self.server.segment_size
                          if self.server.segment_size > 0
                          else 4096 ])
        self.out_buffer = self.out_buffer[num_sent:]
        self.last_segment_time = time.time()
        if len(self.out_buffer) == 0 and closing:
            self.handle_close()
    
    def in_pause(self):
        return
            self.segment_gap != 0 and
            time.time() - self.last_segment_time
                < self.segment_gap / 1000.0
    
    def writable(self):
        if in_pause(self):
            return False;
        return asyncore.dispatcher_with_send.writable(self)
        
    def send(self, data):
        self.out_buffer = self.out_buffer + data
        if !self.in_pause():
            self.initiate_send()
            
    def readable(self):
        return pair.ready
        
    def handle_read(self):
        pair.send(self.recv(MAX_MESSAGE_SIZE))
        
    def handle_close(self):
        self.ready = False
        self.closing = True
        pair.closing = True
        self.close()

class SelfProxy(asyncore.dispatcher):

    def __init__(self, mode = CLIENT_MODE, listen_host, listen_port, forward_host, forward_port, segment_size, segment_gap):
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
            if conn.ready:
                conn.handle_close()
                
    def stop(self):
        self.handle_close()
    
    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, _ = pair
            accepted_conn = ProxyConnection(sock=sock)
            forward_conn = ProxyConnection(pair=accepted_conn)
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
