import abc
import time

from helpers import deproxy, tf_cfg, stateful

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class BaseDeproxyClient(deproxy.Client):

    def __init__(self, *args, **kwargs):
        deproxy.Client.__init__(self, *args, **kwargs)
        self.polling_lock = None
        self.stop_procedures = [self.__stop_client]

    def set_events(self, polling_lock):
        self.polling_lock = polling_lock

    def __stop_client(self):
        tf_cfg.dbg(4, '\tStop deproxy client')
        if self.polling_lock != None:
            self.polling_lock.acquire()
        try:
            self.close()
            self.addr = self.orig_addr
        except Exception as e:
            tf_cfg.dbg(2, "Exception while start: %s" % str(e))
            if self.polling_lock != None:
                self.polling_lock.release()
            raise e
        if self.polling_lock != None:
            self.polling_lock.release()

    def run_start(self):
        if self.polling_lock != None:
            self.polling_lock.acquire()
        try:
            deproxy.Client.run_start(self)
        except Exception as e:
            tf_cfg.dbg(2, "Exception while start: %s" % str(e))
            if self.polling_lock != None:
                self.polling_lock.release()
            raise e
        if self.polling_lock != None:
            self.polling_lock.release()

    def handle_read(self):
        self.response_buffer += self.recv(deproxy.MAX_MESSAGE_SIZE)
        if not self.response_buffer:
            return
        tf_cfg.dbg(4, '\tDeproxy: Client: Receive response.')
        tf_cfg.dbg(5, self.response_buffer)
        try:
            if self.request != None:
                method = self.request.method
            else:
                method = 'INVALID'
            response = deproxy.Response(self.response_buffer,
                                method=method)
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
        try:
            self.request = deproxy.Request(request)
        except:
            tf_cfg.dbg(2, "Can't parse request")
            self.request = None
        self.request_buffer = request

    @abc.abstractmethod
    def recieve_response(self, response):
        raise NotImplementedError("Not implemented 'recieve_response()'")

class DeproxyClient(BaseDeproxyClient):
    last_response = None
    responses = []
    nr = 0

    def recieve_response(self, response):
        tf_cfg.dbg(4, "Recieved response: %s" % str(response.msg))
        self.responses.append(response)
        self.last_response = response

    def make_request(self, request):
        self.nr = len(self.responses)
        BaseDeproxyClient.make_request(self, request)

    def wait_for_response(self, timeout=5):
        if self.state != stateful.STATE_STARTED:
            return False

        t0 = time.time()
        while len(self.responses) == self.nr:
            t = time.time()
            if t - t0 > timeout:
                return False
            time.sleep(0.01)
        return True
