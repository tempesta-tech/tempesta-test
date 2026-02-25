__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2026 Tempesta Technologies, Inc."
__license__ = "GPL2"


import abc
import dataclasses
import ssl
import sys
import time
from collections import defaultdict
from typing import Dict, List, Optional, Union

import h2.connection
from h2.connection import AllowedStreamIDs, ConnectionState
from h2.errors import ErrorCodes
from h2.events import (
    ConnectionTerminated,
    DataReceived,
    PingAckReceived,
    ResponseReceived,
    SettingsAcknowledged,
    StreamEnded,
    StreamReset,
    TrailersReceived,
    WindowUpdated,
)
from h2.settings import SettingCodes, Settings
from h2.stream import StreamInputs
from hpack import Encoder

import run_config
from framework.deproxy import deproxy_message
from framework.deproxy.deproxy_base import BaseDeproxy
from framework.deproxy.deproxy_message import ParseError
from framework.helpers import error, tf_cfg, util
from framework.services import stateful


class BaseDeproxyClient(BaseDeproxy, abc.ABC):
    def __init__(
        self,
        # BaseDeproxy
        *,
        id_,
        deproxy_auto_parser,
        port: int,
        bind_addr: Optional[str],
        segment_size: int,
        segment_gap: int,
        is_ipv6: bool,
        # BaseDeproxyClient
        conn_addr: Optional[str],
        is_ssl: bool,
        server_hostname: str,
    ):
        # Initialize the `BaseDeproxy`
        super().__init__(
            id_=id_,
            deproxy_auto_parser=deproxy_auto_parser,
            port=port,
            bind_addr=bind_addr,
            segment_size=segment_size,
            segment_gap=segment_gap,
            is_ipv6=is_ipv6,
        )

        self.writable = self._in_connecting_state
        self._handle_write = self.__setup_write

        self.ssl = is_ssl
        self._is_http2 = isinstance(self, DeproxyClientH2)
        self._create_context()
        self.server_hostname = server_hostname

        self.request_buffer = ""
        self.response_buffer = ""
        self.conn_addr = conn_addr
        self.conn_is_closed = True
        self.__error_codes: list[Exception | ErrorCodes] = []

        self.rps = 0
        self.parsing = True

        self.simple_get = self.create_request("GET", headers=[])

    def _create_context(self):
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if run_config.SAVE_SECRETS:
            self._context.keylog_filename = "secrets.txt"
        self._context.check_hostname = False
        self._context.verify_mode = ssl.CERT_NONE
        if self._is_http2:
            self._context.set_alpn_protocols(["h2"])
            # Disable old proto
            self._context.options |= (
                ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            )
            # RFC 9113 Section 9.2.1: A deployment of HTTP/2 over TLS 1.2 MUST disable
            # compression.
            self._context.options |= ssl.OP_NO_COMPRESSION

    @property
    def statuses(self) -> Dict[int, int]:
        """
        Be aware that number of HTTP responses (and hence statuses) can be unequal to number of
        TCP responses.

        Example case: we have request_rate=4 and ip_block on. Client maked 4-th request and received
        TCP ACK, but did't received HTTP response yet (it should become in separate TCP packet).
        After this, 5-th request proceed, and client's IP is blocked. In this case we will have only
        3 responses despite the fact that request_rate=4.
        """
        d = defaultdict(lambda: 0)
        for r in self.responses:
            d[int(r.status)] += 1
        return dict(d)

    @property
    def last_response(self) -> Optional[deproxy_message.Response | deproxy_message.H2Response]:
        if not self.responses:
            return None
        return self.responses[-1]

    @property
    def request_buffers(self) -> List[bytes]:
        return self._request_buffers

    @property
    def ack_cnt(self):
        return self._ack_cnt

    @abc.abstractmethod
    def _add_to_request_buffers(self, *args, **kwargs) -> None: ...

    def _add_error_code(self, error_code: Exception | ErrorCodes) -> None:
        self.__error_codes.append(error_code)

    def assert_error_code(
        self, *, expected_error_code: Exception | ErrorCodes, msg: str = ""
    ) -> None:
        """
        We should not check error codes for TCP segmentation
        because we cannot control the sequence of receiving from Tempesta.
        In some cases, RST TCP will be received earlier.
        """
        if not self.segment_size:
            assert (
                expected_error_code in self.__error_codes
            ), f"{expected_error_code} not found in {self.__error_codes}\n{msg}"

    def _in_connecting_state(self):
        return self.connecting

    def _has_pending_data(self):
        if self.cur_req_num >= self.nrreq:
            return False
        if time.time() < self.next_request_time():
            return False
        if (
            self.segment_gap != 0
            and time.time() - self.last_segment_time < self.segment_gap / 1000.0
        ):
            return False
        return True

    def _send_data(self):
        """Send data from `self.request_buffers` and cut them."""
        reqs = self.request_buffers[self.cur_req_num]

        sent = self._send(reqs[: self.segment_size] if self.segment_size else reqs)
        if sent < 0:
            return
        self.last_segment_time = time.time()
        self.request_buffers[self.cur_req_num] = reqs[sent:]
        if len(self.request_buffers[self.cur_req_num]) == 0:
            self.cur_req_num += 1
            self._http_logger.info(
                f"A request was send. The current number of a request - {self.cur_req_num}"
            )
        elif not self.segment_size:
            self._tcp_logger.info(
                f"{sent} bytes sent. {len(self.request_buffers[self.cur_req_num])} bytes left."
            )

    def __setup_write(self):
        self.writable = self._has_pending_data
        self._handle_write = self._send_data

        # Connection established and client has pending data to send
        if self.writable():
            self._handle_write()

    def _handle_connect(self):
        if self.ssl:
            self._socket = self._context.wrap_socket(
                self._socket, do_handshake_on_connect=False, server_hostname=self.server_hostname
            )
        self.conn_is_closed = False
        self.start_time = time.time()

    def _handle_close(self):
        super()._handle_close()
        self.writable = self._in_connecting_state
        self._handle_write = self.__setup_write
        self.conn_is_closed = True

    def _handle_error(self):
        type_error, v, _ = sys.exc_info()
        self._add_error_code(type_error)
        self._tcp_logger.warning(f"Receive error - {type_error} with message - {v}")

        if type_error == ParseError:
            self._handle_close()
            raise v
        elif type_error in (
            ssl.SSLWantReadError,
            ssl.SSLWantWriteError,
            ConnectionRefusedError,
            AssertionError,
        ):
            # SSLWantReadError and SSLWantWriteError - Need to receive more data before decryption
            # can start.
            # ConnectionRefusedError and AssertionError - RST is legitimate case
            pass
        elif type_error == ssl.SSLEOFError:
            # This may happen if a TCP socket is closed without sending TLS close alert. See #1778
            self._handle_close()
        else:
            self._handle_close()
            error.bug("\tDeproxy: Client: %s" % v)

    def set_rps(self, rps):
        self.rps = rps

    def _stop_deproxy(self):
        self._handle_close()

    def _run_deproxy(self):
        self._create_socket()
        if self.bind_addr:
            self._bind(
                (self.bind_addr, 0),
            )
            self._src_ip, self._src_port, *_ = self._socket.getsockname()

        self._tcp_logger.info(f"Trying to connect to {self.conn_addr}:{self.port}.")
        self._connect((self.conn_addr, self.port))

    @abc.abstractmethod
    def _handle_read(self): ...

    def next_request_time(self):
        if self.rps == 0:
            return self.start_time
        return self.start_time + float(self.cur_req_num) / self.rps

    @abc.abstractmethod
    def make_requests(self, requests): ...

    @abc.abstractmethod
    def make_request(self, request, **kwargs): ...

    async def send_request(
        self, request, expected_status_code: Optional[str] = None, timeout=5
    ) -> None:
        """
        Form and send one HTTP request. And also check that the client has received a response and
        the status code matches.
        """
        curr_responses = len(self.responses)

        self.make_request(request)
        await self.wait_for_response(timeout=timeout, strict=bool(expected_status_code))

        if expected_status_code:
            assert curr_responses + 1 == len(self.responses), "Deproxy client has lost response."
            assert expected_status_code in self.last_response.status, (
                f"HTTP response status codes mismatch. Expected - {expected_status_code}. "
                + f"Received - {self.last_response.status}"
            )

    def send_bytes(self, data: bytes, expect_response=False):
        self._add_to_request_buffers(data=data, end_stream=None)
        self.nrreq += 1
        if expect_response:
            self.valid_req_num += 1

    async def wait_for_connection_open(self, timeout=5, strict=False, adjust_timeout=True):
        """
        Try to use strict mode whenever it's possible
        to prevent tests from hard to detect errors.
        """
        timeout_not_exceeded = await util.wait_until(
            lambda: not self.conn_is_active,
            timeout,
            abort_cond=lambda: not self.connecting,
            adjust_timeout=adjust_timeout,
        )
        if strict:
            assert (
                timeout_not_exceeded != False
            ), f"Timeout exceeded while waiting connection open: {timeout}"
        return timeout_not_exceeded

    async def wait_for_connection_close(self, timeout=5, strict=False, adjust_timeout=True):
        """
        Try to use strict mode whenever it's possible
        to prevent tests from hard to detect errors.
        """
        timeout_not_exceeded = await util.wait_until(
            lambda: not self.connection_is_closed(),
            timeout,
            abort_cond=lambda: self.state == stateful.STATE_ERROR,
            adjust_timeout=adjust_timeout,
        )
        if strict:
            assert (
                timeout_not_exceeded != False
            ), f"Timeout exceeded while waiting connection close: {timeout}"
        return timeout_not_exceeded

    async def wait_for_response(
        self, timeout=5, strict=False, adjust_timeout=True, n: Optional[int] = None
    ):
        """
        Try to use strict mode whenever it's possible
        to prevent tests from hard to detect errors.
        """
        timeout_not_exceeded = await util.wait_until(
            lambda: len(self.responses) < (n or self.valid_req_num),
            timeout,
            abort_cond=lambda: self.connection_is_closed() and not self.connecting,
            adjust_timeout=adjust_timeout,
        )
        if strict:
            assert (
                timeout_not_exceeded != False
            ), f"Timeout exceeded while waiting response: {timeout}"
        return timeout_not_exceeded

    def receive_response(self, response: deproxy_message.Response) -> None:
        self.responses.append(response)
        self.clear_last_response_buffer = True
        self._http_logger.info(
            f"A response was receive. The response status={response.status}. "
            f"The current number of responses - {self.nrresp}."
        )

        if self._deproxy_auto_parser.parsing:
            self._deproxy_auto_parser.check_expected_response(
                self.last_response, is_http2=self._is_http2
            )

    def clear_stats(self):
        super().clear_stats()
        self.nrresp = 0  # number of responses that the client received
        self.nrreq = 0  # number of requests that the client must send
        self._request_buffers: List[bytes] = []
        # The HTTP1 client must be informed about a request method to parse body.
        # So we store all request methods. See `parse_body` method in Response.
        self.methods = []
        self.start_time = 0
        self.valid_req_num = 0  # number of requests that are expected to receive responses
        # number of the current request to send. It needed for RPS and TCP segmentation
        self.cur_req_num = 0
        # This state variable contains a timestamp of the last segment sent
        self.last_segment_time = 0
        self.responses: List[deproxy_message.Response] = list()
        self._ack_cnt = 0
        self._src_ip = None
        self._src_port = None

    def connection_is_closed(self):
        return self.conn_is_closed

    def selected_alpn_protocol(self):
        if isinstance(self._socket, ssl.SSLSocket):
            return self._socket.selected_alpn_protocol()
        return None

    @property
    def src_ip(self) -> str | None:
        return self._src_ip

    @property
    def src_port(self) -> int | None:
        return self._src_port

    @property
    def is_http2(self) -> bool:
        return self._is_http2

    @property
    def conn_is_active(self):
        return self.connected

    @property
    def conn_addr(self) -> str:
        return str(self._conn_addr)

    @conn_addr.setter
    def conn_addr(self, conn_addr: str) -> None:
        self._conn_addr = self._set_and_check_ip_addr(conn_addr)


class DeproxyClient(BaseDeproxyClient):
    def make_requests(self, requests: list[deproxy_message.Request | str], pipelined=False) -> None:
        """
        if pipelined is True:
            This method try to send requests in one TCP frame.
            Frame size - 64 KB for local setup and 1500 B for remote.
        Invalid pipelined requests works with list[str].
        """
        if pipelined:
            for request in requests:
                self.__check_request(request)

            requests = [
                request if isinstance(request, str) else request.msg for request in requests
            ]

            req_buf_len = len(self.request_buffers)
            self._add_to_request_buffers("".join(requests))
            self.valid_req_num += len(requests)

            self.nrreq += len(self.request_buffers) - req_buf_len
        else:
            for request in requests:
                self.make_request(request)

    def make_request(self, request: Union[str, deproxy_message.Request], **kwargs) -> None:
        """Send one HTTP request"""
        self.__check_request(request)

        self.valid_req_num += 1
        self._add_to_request_buffers(request if isinstance(request, str) else request.msg)
        self.nrreq += 1

    def __check_request(self, request: str | deproxy_message.Request) -> None:
        if self.parsing and isinstance(request, str):
            self._http_logger.info("Request parsing is running.")
            req = deproxy_message.Request(request)
            expected_request = request.encode()
            self.methods.append(req.method)
            if request[req.original_length :]:
                raise deproxy_message.ParseError("Request has excess symbols.")
            self._http_logger.info("Request parsing is complete.")
        elif isinstance(request, deproxy_message.Request):
            self.methods.append(request.method)

            if request.headers.get("expect") == "100-continue" and not request.body:
                self.methods.append(request.method)

            expected_request = request.msg.encode()
        else:
            self._http_logger.info("Request parsing has been disabled.")
            self.methods.append(request.split(" ")[0])
            expected_request = request.encode()

        if self._deproxy_auto_parser.parsing:
            self._deproxy_auto_parser.prepare_expected_request(expected_request, client=self)

    @staticmethod
    def create_request(
        method,
        headers,
        uri="/",
        date=None,
        body="",
        version="HTTP/1.1",
        authority=tf_cfg.cfg.get("Client", "hostname"),
        *args,
        **kwargs,
    ) -> deproxy_message.Request:
        return deproxy_message.Request.create(
            method=method,
            headers=headers,
            authority=authority,
            uri=uri,
            version=version,
            date=date,
            body=body,
        )

    def _handle_read(self):
        self.response_buffer += self._recv(deproxy_message.MAX_MESSAGE_SIZE).decode()
        if not self.response_buffer:
            return
        while len(self.response_buffer) > 0:
            try:
                method = self.methods[self.nrresp]
                response = deproxy_message.Response(self.response_buffer, method=method)
                self.response_buffer = self.response_buffer[response.original_length :]
            except deproxy_message.IncompleteMessage:
                self._http_logger.debug(f"Receive IncompleteMessage")
                return
            except deproxy_message.ParseError:
                self._http_logger.error(
                    f"Can't parse message\n<<<<\n{self.response_buffer}\n>>>>", exc_info=True
                )
                raise
            self.nrresp += 1
            self.receive_response(response)

    def _add_to_request_buffers(self, data, *_, **__) -> None:
        data = data if isinstance(data, list) else [data]
        for request in data:
            self._request_buffers.append(
                request if isinstance(request, bytes) else request.encode()
            )


class HuffmanEncoder(Encoder):
    """Override method to disable Huffman encoding. Encoding is enabled by default."""

    huffman: bool = True

    def encode(self, headers, huffman=True):
        return super().encode(headers=headers, huffman=self.huffman)


@dataclasses.dataclass
class ReqBodyBuffer:
    body: bytes | None
    stream_id: int | None
    end_stream: bool | None


class DeproxyClientH2(BaseDeproxyClient):
    @property
    def ping_received(self) -> int:
        return self._ping_received

    @property
    def req_body_buffers(self) -> List[ReqBodyBuffer]:
        return self._req_body_buffers

    def run_start(self):
        super(DeproxyClientH2, self).run_start()
        self.update_initial_settings()

    def reinit_hpack_encoder(self):
        self.encoder = HuffmanEncoder()
        self.h2_connection.encoder = HuffmanEncoder()

    def make_requests(self, requests, huffman=True, *args, **kwargs):
        for request in requests:
            self.make_request(request, huffman=huffman)

    def make_request(
        self,
        request: Union[tuple, list, str, deproxy_message.H2Request],
        end_stream=True,
        priority_weight=None,
        priority_depends_on=None,
        priority_exclusive=None,
        huffman=True,
    ):
        """
        Add request to buffers and change counters.
        Args:
            request:
                str - send data frame;
                list - send headers frame;
                tuple - send headers and data frame in one TCP-packet;
            end_stream (bool) - set END_STREAM flag for frame;
            huffman (bool) - enable or disable Huffman encoding;
        """
        self.h2_connection.encoder.huffman = huffman

        if not self.parsing:
            self.h2_connection.config.normalize_outbound_headers = False
            self.h2_connection.config.validate_inbound_headers = False
            self.h2_connection.config.validate_outbound_headers = False

        request = request.msg if isinstance(request, deproxy_message.H2Request) else request

        self._add_to_request_buffers(
            data=request,
            end_stream=end_stream,
            priority_weight=priority_weight,
            priority_depends_on=priority_depends_on,
            priority_exclusive=priority_exclusive,
        )

        self.nrreq += 1
        if end_stream:
            self.stream_id += 2
            self.valid_req_num += 1

    @staticmethod
    def create_request(
        method,
        headers,
        uri="/",
        date=None,
        body="",
        version="HTTP/2",
        authority=tf_cfg.cfg.get("Client", "hostname"),
        *args,
        **kwargs,
    ) -> deproxy_message.H2Request:
        return deproxy_message.H2Request.create(
            method=method,
            headers=headers,
            authority=authority,
            uri=uri,
            version=version,
            date=date,
            body=body,
        )

    def update_initial_settings(
        self,
        header_table_size: int = None,
        enable_push: int = None,
        max_concurrent_stream: int = None,
        initial_window_size: int = None,
        max_frame_size: int = None,
        max_header_list_size: int = None,
    ) -> None:
        """Update initial SETTINGS frame and add preamble + SETTINGS frame in `data_to_send`."""
        self.h2_connection = h2.connection.H2Connection()
        self.h2_connection.encoder = HuffmanEncoder()

        new_settings = self.__generate_new_settings(
            header_table_size,
            enable_push,
            max_concurrent_stream,
            initial_window_size,
            max_frame_size,
            max_header_list_size,
        )

        # if settings is empty, we should not change them
        if new_settings:
            self.h2_connection.local_settings = Settings(initial_values=new_settings)
            self.h2_connection.local_settings.update(new_settings)

        self.h2_connection.initiate_connection()

    def send_settings_frame(
        self,
        header_table_size: int = None,
        enable_push: int = None,
        max_concurrent_stream: int = None,
        initial_window_size: int = None,
        max_frame_size: int = None,
        max_header_list_size: int = None,
    ) -> None:
        self.ack_settings = False

        new_settings = self.__generate_new_settings(
            header_table_size,
            enable_push,
            max_concurrent_stream,
            initial_window_size,
            max_frame_size,
            max_header_list_size,
        )

        self.h2_connection.update_settings(new_settings)

        self.send_bytes(data=self.h2_connection.data_to_send())

    async def wait_for_ack_settings(self, timeout=5):
        """Wait SETTINGS frame with ack flag."""
        return await util.wait_until(
            lambda: not self.ack_settings,
            timeout,
            abort_cond=lambda: self.connection_is_closed() and not self.connecting,
        )

    async def wait_for_reset_stream(self, stream_id: int, timeout=5):
        """Wait RST_STREAM frame for stream."""
        return await util.wait_until(
            lambda: not self.h2_connection._stream_is_closed_by_reset(stream_id=stream_id),
            timeout,
            abort_cond=lambda: self.connection_is_closed() and not self.connecting,
        )

    async def wait_for_headers_frame(self, stream_id: int, timeout=5):
        """Wait HEADERS frame for stream."""
        stream: h2.connection.H2Stream = self.h2_connection._get_stream_by_id(stream_id=stream_id)
        return await util.wait_until(
            lambda: not stream.state_machine.headers_received,
            timeout,
            abort_cond=lambda: self.connection_is_closed() and not self.connecting,
        )

    async def wait_for_ping_frames(self, ping_count: int, timeout=5):
        return await util.wait_until(
            lambda: self._ping_received < ping_count,
            timeout,
            abort_cond=lambda: self.connection_is_closed() and not self.connecting,
        )

    @property
    def auto_flow_control(self) -> bool:
        return self._auto_flow_control

    @auto_flow_control.setter
    def auto_flow_control(self, auto_flow_control: bool) -> None:
        self._auto_flow_control = auto_flow_control

    def increment_flow_control_window(self, stream_id, flow_controlled_length):
        if self.h2_connection.state_machine.state != ConnectionState.CLOSED:
            self.h2_connection.increment_flow_control_window(
                increment=flow_controlled_length, stream_id=None
            )
            if (
                self.h2_connection.streams.get(stream_id)
                and self.h2_connection._get_stream_by_id(stream_id).state_machine.state
                != h2.stream.StreamState.CLOSED
            ):
                self.h2_connection.increment_flow_control_window(
                    increment=flow_controlled_length, stream_id=stream_id
                )

        self.send_bytes(self.h2_connection.data_to_send())

    def _handle_read(self):
        self.response_buffer = self._recv(deproxy_message.MAX_MESSAGE_SIZE)
        if not self.response_buffer:
            return

        if self.clear_last_response_buffer:
            self.clear_last_response_buffer = False
            self.last_response_buffer = bytes()

        self.last_response_buffer += self.response_buffer
        try:
            events = self.h2_connection.receive_data(self.response_buffer)

            self._http_logger.info("Receive 'h2_connection' events")
            self._http_logger.debug(f"{events}")
            for event in events:
                if isinstance(event, ResponseReceived):
                    # H2Connection returns ResponseReceived event when HEADERS and
                    # all CONTINUATION frames with END_HEADERS flag are received.
                    headers = self.__binary_headers_to_string(event.headers)

                    response = deproxy_message.H2Response(
                        headers + "\r\n", method="", body_parsing=False
                    )

                    self.active_responses[event.stream_id] = response

                elif isinstance(event, DataReceived):
                    body = event.data.decode()
                    response = self.active_responses.get(event.stream_id)
                    response.body += body
                    if self.auto_flow_control:
                        self.increment_flow_control_window(
                            event.stream_id, event.flow_controlled_length
                        )
                elif isinstance(event, TrailersReceived):
                    response = self.active_responses.get(event.stream_id)
                    for trailer in event.headers:
                        response.trailer.add(trailer[0].decode(), trailer[1].decode())
                elif isinstance(event, StreamEnded):
                    response = self.active_responses.pop(event.stream_id, None)
                    if response is None:
                        return
                    self.response_sequence.append(event.stream_id)
                    self.receive_response(response)
                    self.nrresp += 1
                elif isinstance(event, StreamReset):
                    self._add_error_code(event.error_code)
                elif isinstance(event, ConnectionTerminated):
                    self._add_error_code(event.error_code)
                    self.last_stream_id = event.last_stream_id
                elif isinstance(event, SettingsAcknowledged):
                    self.ack_settings = True
                    self._ack_cnt += 1
                    if event == events[-1]:
                        # TODO should be changed by issue #358
                        self._handle_read()
                elif isinstance(event, WindowUpdated):
                    if event == events[-1]:
                        # TODO should be changed by issue #358
                        self._handle_read()
                    else:
                        continue
                elif isinstance(event, PingAckReceived):
                    self._ping_received += 1
                    if event == events[-1]:
                        # TODO should be changed by issue #358
                        self._handle_read()
                # TODO should be changed by issue #358
                else:
                    self._handle_read()

        except deproxy_message.IncompleteMessage:
            self._http_logger.debug(f"Receive IncompleteMessage")
            return
        except deproxy_message.ParseError as e:
            self._http_logger.error(
                f"Can't parse message\n<<<<\n{self.response_buffer}\n>>>>", exc_info=True
            )
            raise

    def _send_data(self):
        """
        Send data from `self.request_buffers` and cut them.
        Move data from `self.req_body_buffers` to `self.request_buffers`
            when `self.request_buffers` is empty for current request.
        Increase `self.cur_req_num` when two buffers are empty for current request.
        Does not send data when flow_control_window is 0.
        """
        cur_req_num = self.cur_req_num

        if self.request_buffers[cur_req_num]:
            super()._send_data()

        body = self.req_body_buffers[cur_req_num].body
        if self.request_buffers[cur_req_num] == b"" and body is not None:
            stream_id = self.req_body_buffers[cur_req_num].stream_id
            end_stream = self.req_body_buffers[cur_req_num].end_stream

            # we must decrease self.cur_req_num in case when client sent HEADERS frame
            # but self._req_body_buffers contain data to send for current request.
            # This happens when both buffers are not empty.
            if self.cur_req_num > cur_req_num:
                self.cur_req_num -= 1

            data_to_send, size = self.__prepare_data_frames(body, end_stream, stream_id)
            # we must use data_to_send here because size may be 0 when DATA frame is empty.
            # For example: make_request(request=b""). In this case size is 0, but data_to_send is
            # empty DATA frame
            if not data_to_send:
                return None
            self._request_buffers[cur_req_num] = data_to_send
            body = self._req_body_buffers[cur_req_num].body
            self._req_body_buffers[cur_req_num].body = None if len(body) == size else body[size:]

    @staticmethod
    def __headers_to_string(headers):
        return "".join(["%s: %s\r\n" % (h, v) for h, v in headers])

    @staticmethod
    def __binary_headers_to_string(headers):
        return "".join(["%s: %s\r\n" % (h.decode(), v.decode()) for h, v in headers])

    @staticmethod
    def __generate_new_settings(
        header_table_size: int = None,
        enable_push: int = None,
        max_concurrent_stream: int = None,
        initial_window_size: int = None,
        max_frame_size: int = None,
        max_header_list_size: int = None,
    ) -> dict:
        new_settings = dict()
        if header_table_size is not None:
            new_settings[SettingCodes.HEADER_TABLE_SIZE] = header_table_size
        if enable_push is not None:
            new_settings[SettingCodes.ENABLE_PUSH] = header_table_size
        if max_concurrent_stream is not None:
            new_settings[SettingCodes.MAX_CONCURRENT_STREAMS] = max_concurrent_stream
        if initial_window_size is not None:
            new_settings[SettingCodes.INITIAL_WINDOW_SIZE] = initial_window_size
        if max_frame_size is not None:
            new_settings[SettingCodes.MAX_FRAME_SIZE] = max_frame_size
        if max_header_list_size is not None:
            new_settings[SettingCodes.MAX_HEADER_LIST_SIZE] = max_header_list_size
        return new_settings

    def __prepare_data_frames(self, body: bytes, end_stream: bool, stream_id: int):
        """
        Get available size for the stream and prepare 1 DATA frame.
        """
        size = min(
            self.h2_connection.max_outbound_frame_size,
            self.h2_connection.local_flow_control_window(stream_id),
        )
        if size == 0:
            return b"", size
        elif len(body) > size:
            data_to_send = body[:size]
            end_stream_ = False
        else:
            data_to_send = body
            end_stream_ = end_stream
            size = len(data_to_send)

        self.h2_connection.send_data(
            stream_id=stream_id,
            data=data_to_send,
            end_stream=end_stream_,
        )
        data_to_send = self.h2_connection.data_to_send()
        return data_to_send, size

    def _add_to_body_buffers(
        self, *, body: bytes | None, stream_id: int = None, end_stream: bool = None
    ) -> None:
        self._req_body_buffers.append(ReqBodyBuffer(body, stream_id, end_stream))

    def _add_to_request_buffers(
        self,
        *,
        data,
        end_stream: bool = None,
        priority_weight=None,
        priority_depends_on=None,
        priority_exclusive=None,
    ) -> None:
        if isinstance(data, bytes):
            # in case when you use `send_bytes` method
            self._request_buffers.append(data)
            self._add_to_body_buffers(body=None, stream_id=None, end_stream=None)
        elif isinstance(data, str):
            # in case when you use `make_request` to sending body
            self._request_buffers.append(b"")
            self._add_to_body_buffers(
                body=data.encode(), stream_id=self.stream_id, end_stream=end_stream
            )
        elif isinstance(data, tuple):
            # in case when you use `make_request` to sending headers + body
            self.h2_connection.send_headers(
                self.stream_id,
                data[0],
                False,
                priority_weight,
                priority_depends_on,
                priority_exclusive,
            )
            self._request_buffers.append(self.h2_connection.data_to_send())
            self._add_to_body_buffers(
                body=data[1].encode(), stream_id=self.stream_id, end_stream=end_stream
            )
        elif isinstance(data, list):
            # in case when you use `make_request` to sending headers
            self.h2_connection.send_headers(
                self.stream_id,
                data,
                end_stream,
                priority_weight,
                priority_depends_on,
                priority_exclusive,
            )
            self._request_buffers.append(self.h2_connection.data_to_send())
            self._add_to_body_buffers(body=None, stream_id=None, end_stream=None)

        if self._deproxy_auto_parser.parsing and end_stream and isinstance(data, (tuple, list)):
            self._deproxy_auto_parser.prepare_expected_request(
                self._deproxy_auto_parser.create_request_from_list_or_tuple(data), client=self
            )

    def __calculate_frame_length(self, pos):
        #: The type byte defined for CONTINUATION frames.
        continuation_type = 0x09

        frame_type = self.last_response_buffer[pos + 3]
        if frame_type != continuation_type:
            return -1
        # TCP/IP use big endian
        return int.from_bytes(self.last_response_buffer[pos : pos + 3], "big")

    def clear_stats(self):
        super().clear_stats()
        self.h2_connection: Optional[h2.connection.H2Connection] = None
        self.stream_id: int = 1
        self.active_responses = {}
        self.ack_settings: bool = False
        self.last_stream_id: Optional[int] = None
        self.last_response_buffer = bytes()
        self.clear_last_response_buffer: bool = False
        self.response_sequence = []
        self._req_body_buffers: List[ReqBodyBuffer] = list()
        self._auto_flow_control = True
        self._ping_received = 0

    def check_header_presence_in_last_response_buffer(self, header: bytes) -> bool:
        if len(header) == 0:
            return True
        if len(header) > len(self.last_response_buffer):
            return False
        for bpos in range(0, len(self.last_response_buffer) - len(header) + 1):
            if self.last_response_buffer[bpos] == header[0]:
                equal = True
                hpos = 0
                skip = 0
                while hpos < len(header):
                    if self.last_response_buffer[bpos + hpos + skip] != header[hpos]:
                        part_len = self.__calculate_frame_length(bpos + hpos + skip)
                        if part_len < 0:
                            equal = False
                            break
                        if part_len > len(header) - hpos:
                            part_len = len(header) - hpos
                        # Skip frame size
                        skip += 9
                        for t in range(0, part_len):
                            if self.last_response_buffer[bpos + hpos + skip] != header[hpos]:
                                equal = False
                                break
                            hpos += 1
                        if not equal:
                            break
                        else:
                            continue
                    hpos += 1
                if equal:
                    return True
        return False

    def init_stream_for_send(self, stream_id: int):
        """
        Get or create stream then set state in which the stream is ready for sending and receiving
        data. Used when need to send raw bytes e.g using send_bytes().
        """
        stream = self.h2_connection._get_or_create_stream(
            stream_id, AllowedStreamIDs(self.h2_connection.config.client_side)
        )
        stream.state_machine.process_input(StreamInputs.SEND_HEADERS)
        return stream
