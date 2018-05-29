import abc
import asyncore
import sys
import threading
import socket
import time

from helpers import deproxy, tf_cfg, error, stateful, remote

import port_checks

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class ServerConnection(asyncore.dispatcher_with_send):

    def __init__(self, server, sock=None, keep_alive=None):
        asyncore.dispatcher_with_send.__init__(self, sock)
        self.server = server
        self.keep_alive = keep_alive
        self.responses_done = 0
        self.request_buffer = ''
        tf_cfg.dbg(6, '\tDeproxy: SrvConnection: New server connection.')

    def send_response(self, response):
        if response.msg:
            tf_cfg.dbg(4, '\tDeproxy: SrvConnection: Send response.')
            tf_cfg.dbg(5, response.msg)
            self.send(response.msg)
        else:
            tf_cfg.dbg(4, '\tDeproxy: SrvConnection: Sending invalid response.')
        if self.keep_alive:
            self.responses_done += 1
            if self.responses_done == self.keep_alive:
                self.handle_close()

    def handle_error(self):
        _, v, _ = sys.exc_info()
        error.bug('\tDeproxy: SrvConnection: %s' % v)

    def handle_close(self):
        tf_cfg.dbg(6, '\tDeproxy: SrvConnection: Close connection.')
        self.close()
        if self.server:
            try:
                self.server.connections.remove(self)
            except ValueError:
                pass

    def handle_read(self):
        self.request_buffer += self.recv(deproxy.MAX_MESSAGE_SIZE)
        try:
            request = deproxy.Request(self.request_buffer)
        except deproxy.IncompliteMessage:
            return
        except deproxy.ParseError:
            tf_cfg.dbg(4, ('Deproxy: SrvConnection: Can\'t parse message\n'
                           '<<<<<\n%s>>>>>'
                           % self.request_buffer))
        # Handler will be called even if buffer is empty.
        if not self.request_buffer:
            return
        tf_cfg.dbg(4, '\tDeproxy: SrvConnection: Recieve request.')
        tf_cfg.dbg(5, self.request_buffer)
        response = self.server.recieve_request(request, self)
        self.request_buffer = ''
        if not response:
            return
        self.send_response(response)

class BaseDeproxyServer(deproxy.Server, port_checks.FreePortsChecker):

    def __init__(self, *args, **kwargs):
        deproxy.Server.__init__(self, *args, **kwargs)
        self.stop_procedures = [self.__stop_server]
        self.is_polling = threading.Event()
        self.sockets_changing = threading.Event()
        self.node = remote.host

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, _ = pair
            handler = ServerConnection(server=self, sock=sock,
                                       keep_alive=self.keep_alive)
            self.connections.append(handler)
            assert len(self.connections) <= self.conns_n, \
                ('Too lot connections, expect %d, got %d'
                 % (self.conns_n, len(self.connections)))

    def run_start(self):
        tf_cfg.dbg(3, '\tDeproxy: Server: Start on %s:%d.' % \
                   (self.ip, self.port))
        self.check_ports_status()
        self.polling_lock.acquire()

        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((self.ip, self.port))
        self.listen(socket.SOMAXCONN)

        self.polling_lock.release()

    def __stop_server(self):
        tf_cfg.dbg(3, '\tDeproxy: Server: Stop on %s:%d.' % (self.ip,
                                                             self.port))
        self.polling_lock.acquire()

        self.close()
        connections = [conn for conn in self.connections]
        for conn in connections:
            conn.handle_close()
        if self.tester:
            self.tester.servers.remove(self)

        self.polling_lock.release()

    def set_events(self, polling_lock):
        self.polling_lock = polling_lock

    def wait_for_connections(self, timeout=1):
        if self.state != stateful.STATE_STARTED:
            return False

        t0 = time.time()
        while len(self.connections) < self.conns_n:
            t = time.time()
            if t - t0 > timeout:
                return False
            time.sleep(0.001) # to prevent redundant CPU usage
        return True

    @abc.abstractmethod
    def recieve_request(self, request, connection):
        raise NotImplementedError("Not implemented 'recieve_request()'")

class StaticDeproxyServer(BaseDeproxyServer):

    def __init__(self, *args, **kwargs):
        self.response = kwargs['response']
        kwargs.pop('response', None)
        BaseDeproxyServer.__init__(self, *args, **kwargs)
        self.last_request = None

    def recieve_request(self, request, connection):
        self.last_request = request
        return deproxy.Response(self.response)
