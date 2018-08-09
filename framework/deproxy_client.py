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
        self.requests = []

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
        while len(self.response_buffer) > 0:
            try:                
                method = self.requests[self.nrresp]
                response = deproxy.Response(self.response_buffer,
                                    method=method)
                self.response_buffer = \
                            self.response_buffer[response.original_length:]
            except deproxy.IncompliteMessage:
                return
            except deproxy.ParseError:
                tf_cfg.dbg(4, ('Deproxy: Client: Can\'t parse message\n'
                               '<<<<<\n%s>>>>>'
                            % self.response_buffer))
                raise
            self.recieve_response(response)
            self.nrresp += 1

            if self.nrreq == self.nrresp and len(self.response_buffer) > 0:
                raise deproxy.ParseError('Garbage after response'
                                         ' end:\n```\n%s\n```\n' % \
                                         self.response_buffer)

    def writable(self):
        return len(self.request_buffer) > 0

    def make_request(self, request):
        tmp = request
        self.requests = []
        while len(request) > 0:
            try:
                req = deproxy.Request(request)
            except:
                tf_cfg.dbg(2, "Can't parse request")
                req = None

            if req == None:
                request = ''
                break
            request = request[req.original_length:]
            self.requests.append(req.method)
        
        if len(request) > 0:
            self.requests.append("INVALID")

        self.nrresp = 0
        self.nrreq = len(self.requests)
        self.request_buffer = tmp
        tf_cfg.dbg(5, "\tRequests: %s" % self.requests)

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
        self.responses = []
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
