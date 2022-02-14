import abc
import time
import socket

from helpers import deproxy, tf_cfg, stateful, selfproxy

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018-2022 Tempesta Technologies, Inc.'
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
        # This parameter controls whether to keep original data with the response
        # (See deproxy.HttpMessage.original_data)
        self.keep_original_data = None
        # Following 2 parameters control heavy chunked testing
        # You can set it programmaticaly or via client config
        # TCP segment size, bytes, 0 for disable, usualy value of 1 is sufficient
        self.segment_size = 0
        # Inter-segment gap, ms, 0 for disable.
        # You usualy do not need it; update timeouts if you use it.
        self.segment_gap = 0
        # This state variable contains a timestamp of the last segment sent
        self.last_segment_time = 0
        # The following 2 variables are used to save destination address and port
        # when overriding to connect via ssl chunking proxy
        self.overriden_addr = None
        self.overriden_port = None
        # a presense of selfproxy
        self.selfproxy_present = False

    def handle_connect(self):
        deproxy.Client.handle_connect(self)
        if self.segment_size and not self.selfproxy_present:
            self.socket.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
        self.start_time = time.time()

    def set_events(self, polling_lock):
        self.polling_lock = polling_lock

    def set_rps(self, rps):
        self.rps = rps

    def __stop_client(self):
        tf_cfg.dbg(4, '\tStop deproxy client')
        self.release_selfproxy()
        if self.polling_lock != None:
            self.polling_lock.acquire()
        try:
            self.close()
        except Exception as e:
            tf_cfg.dbg(2, "Exception while stop: %s" % str(e))
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
        if self.ssl and self.segment_size != 0:
            self.insert_selfproxy()
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
                                    method=method,
                                keep_original_data=self.keep_original_data)
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
        if (self.segment_gap != 0 and not self.selfproxy_present and
            time.time() - self.last_segment_time < self.segment_gap / 1000.0):
            return False;
        return True

    def next_request_time(self):
        if self.rps == 0:
            return self.start_time
        return self.start_time + float(self.cur_req_num) / self.rps

    def handle_write(self):
        reqs = self.request_buffers
        tf_cfg.dbg(4, '\tDeproxy: Client: Send request to Tempesta.')
        tf_cfg.dbg(5, reqs[self.cur_req_num])
        if self.segment_size != 0 and not self.selfproxy_present:
            sent = self.send(reqs[self.cur_req_num][:self.segment_size])
        else:
            sent = self.send(reqs[self.cur_req_num])
        if sent < 0:
            return
        self.last_segment_time = time.time()
        reqs[self.cur_req_num] = reqs[self.cur_req_num][sent:]
        if len(reqs[self.cur_req_num]) == 0:
            self.cur_req_num += 1

    def make_requests(self, requests):
        request_buffers = []
        methods = []
        valid_req_num = 0
        if self.selfproxy_present:
            self.update_selfproxy()
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

    def insert_selfproxy(self):
        # inserting the chunking proxy between ssl client and server
        if not self.ssl or self.segment_size == 0:
            return
        selfproxy.request_client_selfproxy(
            listen_host = "127.0.0.1",
            listen_port = selfproxy.CLIENT_MODE_PORT_REPLACE,
            forward_host = self.conn_addr,
            forward_port = self.port,
            segment_size = self.segment_size,
            segment_gap = self.segment_gap)
        self.overriden_addr = self.conn_addr
        self.overriden_port = self.port
        self.conn_addr = "127.0.0.1"
        self.port = selfproxy.CLIENT_MODE_PORT_REPLACE
        self.selfproxy_present = True

    def release_selfproxy(self):
        # action reverse to insert_selfproxy
        if self.selfproxy_present:
            selfproxy.release_client_selfproxy()
            self.selfproxy_present = False
        if self.overriden_addr is not None:
            self.conn_addr = self.overriden_addr
            self.overriden_addr = None
        if self.overriden_port is not None:
            self.port = self.overriden_port
            self.overriden_port = None

    def update_selfproxy(self):
        # update chunking parameters
        if self.selfproxy_present:
            selfproxy.update_client_selfproxy_chunking(
                self.segment_size, self.segment_gap)


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
