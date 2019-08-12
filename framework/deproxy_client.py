import abc
import time

from helpers import deproxy, tf_cfg, stateful

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018-2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class BaseDeproxyClient(deproxy.Client):

    def __init__(self, *args, **kwargs):
        deproxy.Client.__init__(self, *args, **kwargs)
        self.polling_lock = None
        self.stop_procedures = [self.__stop_client]
        self.nrresp = 0
        self.nrreq = 0
        self.request_buffers = []
        self.methods = []
        self.start_time = 0
        self.rps = 0
        self.valid_req_num = 0
        self.cur_req_num = 0

    def handle_connect(self):
        deproxy.Client.handle_connect(self)
        self.start_time = time.time()

    def set_events(self, polling_lock):
        self.polling_lock = polling_lock

    def set_rps(self, rps):
        self.rps = rps

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
        self.request_buffers = []
        self.methods = []
        self.start_time = 0
        self.valid_req_num = 0
        self.cur_req_num = 0
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
        if self.cur_req_num >= self.nrreq:
            return False
        if time.time() < self.next_request_time():
            return False
        return True

    def next_request_time(self):
        if self.rps == 0:
            return self.start_time
        return self.start_time + float(self.cur_req_num) / self.rps

    def handle_write(self):
        reqs = self.request_buffers
        tf_cfg.dbg(4, '\tDeproxy: Client: Send request to Tempesta.')
        tf_cfg.dbg(5, reqs[self.cur_req_num])
        sent = self.send(reqs[self.cur_req_num])
        if sent < 0:
            return
        reqs[self.cur_req_num] = reqs[self.cur_req_num][sent:]
        if len(reqs[self.cur_req_num]) == 0:
            self.cur_req_num += 1

    def make_requests(self, requests):
        request_buffers = []
        methods = []
        valid_req_num = 0
        while len(requests) > 0:
            try:
                req = deproxy.Request(requests)
            except:
                tf_cfg.dbg(2, "Can't parse request")
                req = None

            if req == None:
                break
            request_buffers.append(requests[:req.original_length])
            methods.append(req.method)
            valid_req_num += 1
            requests = requests[req.original_length:]

        if len(requests) > 0:
            request_buffers.append(requests)
            methods.append("INVALID")

        if self.cur_req_num >= self.nrreq:
            self.nrresp = 0
            self.nrreq = 0
            self.request_buffers = []
            self.methods = []
            self.start_time = time.time()
            self.cur_req_num = 0

        self.request_buffers.extend(request_buffers)
        self.methods.extend(methods)
        self.valid_req_num += valid_req_num
        self.nrreq += len(self.methods)

    # need for compatibility
    def make_request(self, request):
        self.make_requests(request)

    @abc.abstractmethod
    def receive_response(self, response):
        raise NotImplementedError("Not implemented 'receive_response()'")


class DeproxyClient(BaseDeproxyClient):
    last_response = None
    responses = []

    def run_start(self):
        BaseDeproxyClient.run_start(self)
        self.responses = []

    def receive_response(self, response):
        self.responses.append(response)
        self.last_response = response

    def wait_for_response(self, timeout=5):
        if self.state != stateful.STATE_STARTED:
            return False

        t0 = time.time()
        while len(self.responses) < self.valid_req_num:
            t = time.time()
            if t - t0 > timeout:
                return False
            time.sleep(0.01)
        return True
