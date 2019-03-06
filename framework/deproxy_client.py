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
        self.nrresp = 0
        self.nrreq = 0
        self.methods = []

    def set_events(self, polling_lock):
        self.polling_lock = polling_lock

    def __stop_client(self):
        tf_cfg.dbg(4, '\tStop deproxy client')
        if self.polling_lock != None:
            self.polling_lock.acquire()
        try:
            self.close()
        except Exception as e:
            tf_cfg.dbg(2, "Exception while start: %s" % str(e))
            if self.polling_lock != None:
                self.polling_lock.release()
            raise e
        if self.polling_lock != None:
            self.polling_lock.release()

    def run_start(self):
        self.nrresp = 0
        self.nrreq = 0
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
        while len(self.response_buffer) > 0 and self.nrreq > self.nrresp:
            try:
                method = self.methods[self.nrresp]
                response = deproxy.Response(self.response_buffer,
                                    method=method)
                self.response_buffer = \
                            self.response_buffer[response.original_length:]
            except deproxy.IncompleteMessage:
                return
            except deproxy.ParseError:
                tf_cfg.dbg(4, ('Deproxy: Client: Can\'t parse message\n'
                               '<<<<<\n%s>>>>>'
                            % self.response_buffer))
                raise
            self.receive_response(response)
            self.nrresp += 1

        if self.nrreq == self.nrresp and len(self.response_buffer) > 0:
            raise deproxy.ParseError('Garbage after response'
                                     ' end:\n```\n%s\n```\n' % \
                                     self.response_buffer)

    def writable(self):
        return len(self.request_buffer) > 0

    def make_requests(self, requests):
        tmp = requests
        self.methods = []
        while len(requests) > 0:
            try:
                req = deproxy.Request(requests)
            except:
                tf_cfg.dbg(2, "Can't parse request")
                req = None

            if req == None:
                self.methods.append("INVALID")
                requests = ''
                break
            requests = requests[req.original_length:]
            self.methods.append(req.method)

        if len(requests) > 0:
            self.methods.append("INVALID")

        self.nrresp = 0
        self.nrreq = len(self.methods)
        self.request_buffer = tmp

    # need for compatibility
    def make_request(self, request):
        self.make_requests(request)

    @abc.abstractmethod
    def receive_response(self, response):
        raise NotImplementedError("Not implemented 'receive_response()'")


class DeproxyClient(BaseDeproxyClient):
    last_response = None
    responses = []
    nr = 0

    def run_start(self):
        BaseDeproxyClient.run_start(self)
        self.responses = []

    def receive_response(self, response):
        self.responses.append(response)
        self.last_response = response

    def make_requests(self, requests):
        self.nr = len(self.responses)
        BaseDeproxyClient.make_requests(self, requests)

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
