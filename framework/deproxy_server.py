import abc
import asyncore
import sys

from helpers import deproxy, tf_cfg, error

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

class BaseDeproxyServer(deproxy.Server):

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
