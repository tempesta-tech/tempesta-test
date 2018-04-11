import abc
from helpers import deproxy, tf_cfg

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class BaseDeproxyClient(deproxy.Client):

    def handle_read(self):
        self.response_buffer += self.recv(deproxy.MAX_MESSAGE_SIZE)
        if not self.response_buffer:
            return
        tf_cfg.dbg(4, '\tDeproxy: Client: Receive response.')
        tf_cfg.dbg(5, self.response_buffer)
        try:
            response = deproxy.Response(self.response_buffer,
                                method=self.request.method)
            self.response_buffer = self.response_buffer[len(response.msg):]
        except deproxy.IncompliteMessage:
            return
        except deproxy.ParseError:
            tf_cfg.dbg(4, ('Deproxy: Client: Can\'t parse message\n'
                           '<<<<<\n%s>>>>>'
                           % self.response_buffer))
            raise
        if len(self.response_buffer) > 0:
            # TODO: take care about pipelined case
            raise deproxy.ParseError('Garbage after response'
                                     ' end:\n```\n%s\n```\n' % \
                                     self.response_buffer)
        self.recieve_response(response)
        self.response_buffer = ''

    def writable(self):
        return len(self.request_buffer) > 0

    def make_request(self, request):
        self.request = deproxy.Request(request)
        self.request_buffer = request

    @abc.abstractmethod
    def recieve_response(self, response):
        raise NotImplementedError("Not implemented 'recieve_response()'")

class LastDeproxyClient(BaseDeproxyClient):
    last_response = None

    def recieve_response(self, response):
        tf_cfg.dbg(4, "Recieved response: %s" % str(response.msg))
        self.last_response = response
