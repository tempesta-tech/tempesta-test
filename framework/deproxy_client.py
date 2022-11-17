import abc
import socket
import time
from io import StringIO

import h2.connection
from h2.events import DataReceived, ResponseReceived, StreamEnded, TrailersReceived

from helpers import deproxy, selfproxy, stateful, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2022 Tempesta Technologies, Inc."
__license__ = "GPL2"


class BaseDeproxyClient(deproxy.Client, abc.ABC):
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
        self.parsing = True

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
        tf_cfg.dbg(4, "\tStop deproxy client")
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
        self.response_buffer += self.recv(deproxy.MAX_MESSAGE_SIZE).decode()
        if not self.response_buffer:
            return
        tf_cfg.dbg(4, "\tDeproxy: Client: Receive response.")
        tf_cfg.dbg(5, self.response_buffer)
        while len(self.response_buffer) > 0 and self.nrreq > self.nrresp:
            try:
                method = self.methods[self.nrresp]
                response = deproxy.Response(
                    self.response_buffer, method=method, keep_original_data=self.keep_original_data
                )
                self.response_buffer = self.response_buffer[response.original_length :]
            except deproxy.IncompleteMessage:
                return
            except deproxy.ParseError:
                tf_cfg.dbg(
                    4,
                    (
                        "Deproxy: Client: Can't parse message\n"
                        "<<<<<\n%s>>>>>" % self.response_buffer
                    ),
                )
                raise
            self.receive_response(response)
            self.nrresp += 1

        if self.nrreq == self.nrresp and len(self.response_buffer) > 0:
            raise deproxy.ParseError(
                "Garbage after response" " end:\n```\n%s\n```\n" % self.response_buffer
            )

    def writable(self):
        if self.cur_req_num >= self.nrreq:
            return False
        if time.time() < self.next_request_time():
            return False
        if (
            self.segment_gap != 0
            and not self.selfproxy_present
            and time.time() - self.last_segment_time < self.segment_gap / 1000.0
        ):
            return False
        return True

    def next_request_time(self):
        if self.rps == 0:
            return self.start_time
        return self.start_time + float(self.cur_req_num) / self.rps

    def handle_write(self):
        reqs = self.request_buffers
        tf_cfg.dbg(4, "\tDeproxy: Client: Send request to Tempesta.")
        tf_cfg.dbg(5, reqs[self.cur_req_num])
        if self.segment_size != 0 and not self.selfproxy_present:
            sent = self.send(reqs[self.cur_req_num][: self.segment_size].encode())
        else:
            self.socket.sendall(reqs[self.cur_req_num].encode())
            sent = len(reqs[self.cur_req_num])
        if sent < 0:
            return
        self.last_segment_time = time.time()
        reqs[self.cur_req_num] = reqs[self.cur_req_num][sent:]
        if len(reqs[self.cur_req_num]) == 0:
            self.cur_req_num += 1

    @abc.abstractmethod
    def make_requests(self, requests):
        raise NotImplementedError("Not implemented 'make_requests()'")

    @abc.abstractmethod
    def make_request(self, request):
        raise NotImplementedError("Not implemented 'make_request()'")

    @abc.abstractmethod
    def receive_response(self, response):
        raise NotImplementedError("Not implemented 'receive_response()'")

    def insert_selfproxy(self):
        # inserting the chunking proxy between ssl client and server
        if not self.ssl or self.segment_size == 0:
            return
        selfproxy.request_client_selfproxy(
            listen_host="127.0.0.1",
            listen_port=selfproxy.CLIENT_MODE_PORT_REPLACE,
            forward_host=self.conn_addr,
            forward_port=self.port,
            segment_size=self.segment_size,
            segment_gap=self.segment_gap,
        )
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
            selfproxy.update_client_selfproxy_chunking(self.segment_size, self.segment_gap)

    def _clear_request_stats(self):
        if self.cur_req_num >= self.nrreq:
            self.nrresp = 0
            self.nrreq = 0
            self.request_buffers = []
            self.methods = []
            self.start_time = time.time()
            self.cur_req_num = 0


class DeproxyClient(BaseDeproxyClient):
    last_response = None
    responses = []
    last_response: deproxy.Response

    def make_requests(self, requests: list or str) -> None:
        """Send pipelined HTTP requests. Requests parsing can be disabled only for list."""
        self._clear_request_stats()
        self.update_selfproxy()

        if isinstance(requests, list):
            for request in requests:
                self.__check_request(request)

            self.request_buffers.extend(requests)
            self.valid_req_num += len(self.request_buffers)
            self.nrreq += len(self.request_buffers)

        elif isinstance(requests, str):
            request_buffers = []
            valid_req_num = 0
            while len(requests) > 0:
                try:
                    tf_cfg.dbg(2, "Request parsing is running.")
                    req = deproxy.Request(requests)
                    tf_cfg.dbg(3, "Request parsing is complete.")
                except Exception as e:
                    tf_cfg.dbg(2, f"Can't parse request. Error msg: {e}")
                    req = None
                if req is None:
                    break

                request_buffers.append(requests[: req.original_length])
                self.methods.append(req.method)
                valid_req_num += 1
                requests = requests[req.original_length :]

            if len(requests) > 0:
                request_buffers.append(requests)
                self.methods.append("INVALID")

            self.request_buffers.extend(request_buffers)
            self.valid_req_num += valid_req_num
            self.nrreq += len(self.methods)

    def make_request(self, request: str) -> None:
        """Send one HTTP request"""
        self._clear_request_stats()
        self.update_selfproxy()

        self.__check_request(request)

        self.valid_req_num += 1
        self.request_buffers.append(request)
        self.nrreq += 1

    def __check_request(self, request: str) -> None:
        if self.parsing:
            tf_cfg.dbg(2, "Request parsing is running.")
            req = deproxy.Request(request)
            self.methods.append(req.method)
            if request[req.original_length :]:
                raise deproxy.ParseError("Request has excess symbols.")
            tf_cfg.dbg(3, "Request parsing is complete.")
        else:
            tf_cfg.dbg(2, "Request parsing has been disabled.")
            self.methods.append(request.split(" ")[0])

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

    def send_request(self, request, expected_status_code: str):
        """
        Form and send one HTTP request. And also check that the client has received a response and
        the status code matches.
        """
        curr_responses = len(self.responses)

        self.make_request(request)
        self.wait_for_response()

        assert curr_responses + 1 == len(self.responses), "Deproxy client has lost response."
        assert expected_status_code in self.last_response.status, (
            f"HTTP response status codes mismatch. Expected - {expected_status_code}. "
            + f"Received - {self.last_response.status}"
        )


class DeproxyClientH2(DeproxyClient):
    last_response: deproxy.H2Response

    def __init__(self, *args, **kwargs):
        DeproxyClient.__init__(self, *args, **kwargs)
        self.h2_connection = None
        self.stream_id = 1
        self.active_responses = {}

    def make_requests(self, requests):
        for request in requests:
            self.make_request(request)

    def make_request(self, request: tuple or list):
        self._clear_request_stats()

        if isinstance(request, tuple):
            headers, body = request
        elif isinstance(request, list):
            headers = request
            body = ""

        if self.h2_connection is None:
            self.h2_connection = h2.connection.H2Connection()
            self.h2_connection.initiate_connection()
            if self.selfproxy_present:
                self.update_selfproxy()

        for header in headers:
            if header[0] == ":method":
                self.methods.append(header[1])

        if not self.parsing:
            self.h2_connection.config.normalize_outbound_headers = False
            self.h2_connection.config.validate_inbound_headers = False
            self.h2_connection.config.validate_outbound_headers = False

        if body != "":
            self.h2_connection.send_headers(self.stream_id, headers)
            self.h2_connection.send_data(self.stream_id, body.encode(), True)
        else:
            self.h2_connection.send_headers(self.stream_id, headers, True)

        self.stream_id += 2
        self.request_buffers.append(self.h2_connection.data_to_send())
        self.valid_req_num += 1
        self.nrreq += 1

    def handle_read(self):
        self.response_buffer = self.recv(deproxy.MAX_MESSAGE_SIZE)
        if not self.response_buffer:
            return

        tf_cfg.dbg(4, "\tDeproxy: Client: Receive response.")
        tf_cfg.dbg(5, self.response_buffer)

        try:
            method = self.methods[self.nrresp]
            events = self.h2_connection.receive_data(self.response_buffer)
            for event in events:
                if isinstance(event, ResponseReceived):
                    headers = self.__binary_headers_to_string(event.headers)

                    response = self.active_responses.get(event.stream_id)
                    if response:
                        stream = StringIO(headers)
                        response.parse_headers(stream)
                        response.update()
                    else:
                        response = deproxy.H2Response(
                            headers + "\r\n",
                            method=method,
                            body_parsing=False,
                            keep_original_data=self.keep_original_data,
                        )

                        self.active_responses[event.stream_id] = response

                elif isinstance(event, DataReceived):
                    body = event.data.decode()
                    response = self.active_responses.get(event.stream_id)
                    response.body += body
                    self.h2_connection.acknowledge_received_data(
                        acknowledged_size=event.flow_controlled_length,
                        stream_id=event.stream_id
                    )
                elif isinstance(event, TrailersReceived):
                    trailers = self.__headers_to_string(event.headers)
                    response = self.active_responses.get(event.stream_id)
                    response.parse_text(str(response.headers) + "\r\n" + response.body + trailers)
                elif isinstance(event, StreamEnded):
                    response = self.active_responses.pop(event.stream_id, None)
                    if response == None:
                        return
                    self.receive_response(response)
                    self.nrresp += 1

        except deproxy.IncompleteMessage:
            tf_cfg.dbg(
                4,
                (
                    "Deproxy: Client: Can't parse incomplete message\n"
                    "<<<<<\n%s>>>>>" % self.response_buffer
                ),
            )
            return
        except deproxy.ParseError:
            tf_cfg.dbg(
                4,
                ("Deproxy: Client: Can't parse message\n" "<<<<<\n%s>>>>>" % self.response_buffer),
            )
            raise

    def handle_write(self):
        reqs = self.request_buffers
        tf_cfg.dbg(4, "\tDeproxy: Client: Send request to Tempesta.")
        tf_cfg.dbg(5, reqs[self.cur_req_num])

        sent = self.send(reqs[self.cur_req_num])
        if sent < 0:
            return

        self.cur_req_num += 1

    def __headers_to_string(self, headers):
        return "".join(["%s: %s\r\n" % (h, v) for h, v in headers])

    def __binary_headers_to_string(self, headers):
        return "".join(["%s: %s\r\n" % (h.decode(), v.decode()) for h, v in headers])
