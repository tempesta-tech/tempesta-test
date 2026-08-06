__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2026 Tempesta Technologies, Inc."
__license__ = "GPL2"


import abc
import asyncio
import dataclasses
import ssl
from collections import defaultdict
from typing import Callable, Dict, List, Optional, Union

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
from framework.deproxy.deproxy_connection import (
    DeproxyBase,
    DeproxyConnection,
    safe_readwrite,
)
from framework.helpers import tf_cfg, util
from framework.services import stateful


class ClientConnection(DeproxyConnection):
    _deproxy: "BaseDeproxyClient"

    def __init__(
        self,
        client: "BaseDeproxyClient",
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        super().__init__(client, reader, writer)
        self._queue = client._queue
        self._start_readwrite()
        self._tcp_logger.debug("New client connection")

    @safe_readwrite
    async def _read_loop(self) -> None:
        resp_buffer = bytearray()
        while self._readwrite.is_set():
            data = await self._reader.read(deproxy_message.MAX_MESSAGE_SIZE)
            if not data:
                await self.close()
                return
            resp_buffer.extend(data)

            while resp_buffer:
                len_ = self._deproxy._process_received_data(resp_buffer)
                if len_ is None:
                    break
                del resp_buffer[:len_]

    @safe_readwrite
    async def _write_loop(self) -> None:
        while self._readwrite.is_set():
            item = await self._queue.get()

            if item is None:
                self._queue.task_done()
                break

            data, count = item
            await self._write_func(data)
            self._queue.task_done()

    def _after_close(self) -> None:
        if self in self._deproxy.connections:
            self._deproxy.remove_connection(connection=self)
        self._deproxy._connecting = False
        self._deproxy._connected = False


class BaseDeproxyClient(DeproxyBase, stateful.Stateful, abc.ABC):
    _connection_factory: Callable[..., ClientConnection]

    def __init__(
        self,
        *,
        # Stateful
        id_,
        # DeproxyBase
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
        rcv_buf_size: int,
    ):
        DeproxyBase.__init__(
            self,
            deproxy_auto_parser=deproxy_auto_parser,
            port=port,
            bind_addr=bind_addr,
            segment_size=segment_size,
            segment_gap=segment_gap,
            is_ipv6=is_ipv6,
            rcv_buf_size=rcv_buf_size,
        )
        stateful.Stateful.__init__(self, id_=id_)
        # state flags
        self._connected: bool = False
        self._connecting: bool = False
        # unchangeable flags
        self.ssl = is_ssl
        self._is_http2 = not isinstance(self, DeproxyClient)
        # changeable flags and params
        self.parsing = True
        self.close_connection_for_tcp_fin = True
        self.server_hostname = server_hostname
        self.conn_addr = conn_addr
        self.rps = 0
        # asyncio
        self._connect_task: Optional[asyncio.Task] = None
        self._queue: asyncio.Queue[tuple[bytes, int] | None] = asyncio.Queue()
        # internal logic
        self._nrresp = 0
        self.__error_codes: list[Exception | ErrorCodes] = []
        self._create_context()
        self.simple_get = self.create_request("GET", headers=[])

    def _add_to_requests_queue(self, data: bytes, *_, **__) -> None:
        """
        Add the finished data to the sending queue.
        The client and the connection work with the same queue
        """
        self._queue.put_nowait((data, 0))

    def _create_context(self):
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if run_config.SAVE_SECRETS:
            self._context.keylog_filename = "secrets.txt"
        self._context.check_hostname = False
        self._context.verify_mode = ssl.CERT_NONE
        if self._is_http2:
            self._context.set_alpn_protocols(["h2"])
            # Disable old proto
            self._context.minimum_version = ssl.TLSVersion.TLSv1_2
            # RFC 9113 Section 9.2.1: A deployment of HTTP/2 over TLS 1.2 MUST disable
            # compression.
            self._context.options |= ssl.OP_NO_COMPRESSION

    @property
    def _connection(self) -> Optional[ClientConnection]:
        if self.connections:
            return self.connections[0]
        return None

    @property
    def is_rst_received(self) -> bool:
        return self._connection.is_rst_received

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

    def _add_error_code(self, error_code: Exception | ErrorCodes) -> None:
        self.__error_codes.append(error_code)

    def assert_error_code(
        self, *, expected_error_code: Exception | ErrorCodes, msg: str = ""
    ) -> None:
        """
        We should not check error codes for TCP segmentation
        because we cannot control the sequence of receiving from Tempesta.
        In some cases, RST TCP will be received earlier.
        It should call after `wait_for_connection_close` or `wait_for_reset_stream`.
        """
        if not self.segment_size:
            assert (
                expected_error_code in self.__error_codes
            ), f"{expected_error_code} not found in {self.__error_codes}\n{msg}"

    async def run_start(self) -> None:
        if self._connecting or self._connected:
            return
        self._connected = False
        self._connecting = True
        self._connect_task = asyncio.create_task(self._connect())

    async def _connect(self) -> None:
        try:
            reader, writer = await asyncio.open_connection(
                host=self.conn_addr,
                port=self.port,
                ssl=self._context if self.ssl else None,
                server_hostname=self.server_hostname if self.ssl else None,
                local_addr=(self.bind_addr, 0) if self.bind_addr else None,
            )
        except (OSError, ssl.SSLError) as exc:
            self._add_error_code(type(exc))
            self._tcp_logger.warning(f"Failed to connect - {type(exc)} with message - {exc}")
            self._connecting = False
            return

        self._connections.append(self._connection_factory(self, reader, writer))
        self._src_ip, self._src_port, *_ = writer.get_extra_info("sockname")

        self._connecting = False
        self._connected = True

        self._tcp_logger.info(f"Connected to {self.conn_addr}:{self.port}.")

    async def _stop_deproxy(self) -> None:
        if self._connection:
            await self._connection.close()
        self.clear_stats()
        self.close_connection_for_tcp_fin = True
        self._connected = False
        self._connecting = False

    @abc.abstractmethod
    def _process_received_data(self, data: bytearray) -> Optional[int]: ...

    @abc.abstractmethod
    def make_requests(self, requests): ...

    @abc.abstractmethod
    def make_request(self, request, **kwargs): ...

    @staticmethod
    @abc.abstractmethod
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
    ) -> deproxy_message.Request: ...

    async def send_request(
        self,
        request: deproxy_message.Request | deproxy_message.H2Request | str,
        expected_status_code: Optional[str] = None,
        timeout: float = 5.0,
        msg: Optional[str] = None,
    ) -> None:
        """
        Form and send one HTTP request. And also check that the client has received a response and
        the status code matches.
        """
        self.make_request(request)
        await self.wait_for_response(timeout=timeout, msg=msg)

        if expected_status_code:
            assert expected_status_code in self.last_response.status, (
                msg
                or f"HTTP response status codes mismatch. Expected - {expected_status_code}. "
                + f"Received - {self.last_response.status}\nThe last response:\n{self.last_response}\n"
            )

    def send_bytes(self, data: bytes, expect_response: bool = False) -> None:
        self._add_to_requests_queue(data=data)
        if expect_response:
            self._valid_req_num += 1

    async def wait_for_connection_open(
        self, timeout: float = 5, adjust_timeout: bool = True, msg: Optional[str] = None
    ) -> None:
        """
        Try to use strict mode whenever it's possible
        to prevent tests from hard to detect errors.
        """
        timeout_not_exceeded = await util.wait_until(
            lambda: not self.conn_is_active,
            timeout,
            abort_cond=lambda: self.state != stateful.STATE_STARTED,
            adjust_timeout=adjust_timeout,
        )
        assert timeout_not_exceeded, f"{timeout_not_exceeded} is not True." + (
            msg or f"Timeout exceeded while waiting connection open: {timeout}"
        )

    async def wait_for_connection_close(
        self,
        timeout: float = 5,
        adjust_timeout: bool = True,
        msg: Optional[str] = None,
    ) -> None:
        """
        Try to use strict mode whenever it's possible
        to prevent tests from hard to detect errors.
        """
        timeout_not_exceeded = await util.wait_until(
            lambda: not self.connection_is_closed,
            timeout,
            abort_cond=lambda: self.state == stateful.STATE_ERROR,
            adjust_timeout=adjust_timeout,
        )
        assert timeout_not_exceeded, f"{timeout_not_exceeded} is not True." + (
            msg or f"Timeout exceeded while waiting connection close: {timeout}"
        )

    async def wait_for_client_sends_requests(
        self, valid_req_num: int = 0, timeout: float = 5, msg: str = ""
    ) -> None:
        """Wait for client sends requests from the buffers."""
        valid_req_num = valid_req_num or self._valid_req_num
        timeout_not_exceeded = await util.wait_until(
            lambda: self._cur_req_num < valid_req_num,
            timeout,
            abort_cond=lambda: self.state != stateful.STATE_STARTED,
        )

        assert timeout_not_exceeded, (
            msg or f"Timeout exceeded while waiting connection close: {timeout}"
        )

    async def wait_for_response(
        self,
        timeout: float = 5,
        adjust_timeout: bool = True,
        n: Optional[int] = None,
        msg: Optional[str] = None,
    ) -> None:
        """
        Try to use strict mode whenever it's possible
        to prevent tests from hard to detect errors.
        """
        timeout_not_exceeded = await util.wait_until(
            lambda: len(self.responses) < (n or self._valid_req_num),
            timeout,
            abort_cond=lambda: self.connection_is_closed and not self._connecting,
            adjust_timeout=adjust_timeout,
        )
        assert timeout_not_exceeded, f"{timeout_not_exceeded} is not True." + (
            msg or f"Timeout exceeded while waiting response: {timeout}"
        )

    def _receive_response(self, response: deproxy_message.Response) -> None:
        self.responses.append(response)
        self._clear_last_response_buffer = True
        self._http_logger.info(
            f"A response was receive. The response status={response.status}. "
            f"The current number of responses - {self._nrresp}."
        )

        if self._deproxy_auto_parser.parsing:
            self._deproxy_auto_parser.check_expected_response(
                self.last_response, is_http2=self._is_http2
            )

    def clear_stats(self):
        super().clear_stats()
        self._nrresp = 0  # number of responses that the client received
        # The HTTP1 client must be informed about a request method to parse body.
        # So we store all request methods. See `parse_body` method in Response.
        self.methods = []
        self._valid_req_num = 0  # number of requests that are expected to receive responses
        # number of the current request to send. It needed for RPS and TCP segmentation
        self._cur_req_num = 0
        # This state variable contains a timestamp of the last segment sent
        self.responses: List[deproxy_message.Response] = list()
        self._src_ip = None
        self._src_port = None

    @property
    def connection_is_closed(self) -> bool:
        return not self._connected

    @property
    def selected_alpn_protocol(self):
        connection = self._connection
        if connection is None:
            return None

        ssl_object = self._connection.ssl_object
        if ssl_object is None:
            return None

        return ssl_object.selected_alpn_protocol()

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
        return self._connected

    @property
    def conn_addr(self) -> str:
        return str(self._conn_addr)

    @conn_addr.setter
    def conn_addr(self, conn_addr: str) -> None:
        self._conn_addr = self._set_and_check_ip_addr(conn_addr)


class DeproxyClient(BaseDeproxyClient):
    _connection_factory = ClientConnection

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
                request.encode() if isinstance(request, str) else request.msg.encode()
                for request in requests
            ]

            self._add_to_requests_queue(b"".join(requests))
            self._valid_req_num += len(requests)

        else:
            for request in requests:
                self.make_request(request)

    def make_request(self, request: Union[str, deproxy_message.Request], **kwargs) -> None:
        """Send one HTTP request"""
        self.__check_request(request)

        self._valid_req_num += 1
        self._add_to_requests_queue(
            request.encode() if isinstance(request, str) else request.msg.encode()
        )

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

    def _process_received_data(self, data: bytearray) -> Optional[int]:
        try:
            method = self.methods[self._nrresp]
            response = deproxy_message.Response(data.decode(), method=method)
            self._nrresp += 1
        except deproxy_message.IncompleteMessage:
            self._http_logger.debug(f"Receive IncompleteMessage")
            return None
        except deproxy_message.ParseError:
            self._http_logger.error(f"Can't parse message\n<<<<\n{data}\n>>>>", exc_info=True)
            raise
        self._receive_response(response)
        return response.original_length


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
    _connection_factory = ClientConnection

    async def run_start(self):
        self.update_initial_settings()
        self._body_queue: asyncio.Queue[ReqBodyBuffer] = asyncio.Queue()
        self._body_event = asyncio.Event()
        await super(DeproxyClientH2, self).run_start()

    async def _connect(self):
        await super()._connect()
        self._body_task = asyncio.create_task(self._body_sending_task())

    async def _body_sending_task(self) -> None:
        while self._connected:
            await self._body_event.wait()

            while self._req_body_buffers and self._connected:
                req_body_buffer = self._req_body_buffers.pop(0)
                body = req_body_buffer.body
                stream_id = req_body_buffer.stream_id
                end_stream = req_body_buffer.end_stream

                data_to_send, size = self.__prepare_data_frames(body, end_stream, stream_id)
                # we must use data_to_send here because size may be 0 when DATA frame is empty.
                # For example: make_request(request=b""). In this case size is 0, but data_to_send is
                # empty DATA frame
                if not data_to_send:
                    self._req_body_buffers.append(req_body_buffer)
                    break
                self._add_to_requests_queue(data=data_to_send)

                if len(body) > size:
                    self._req_body_buffers.append(ReqBodyBuffer(body[size:], stream_id, end_stream))
                await asyncio.sleep(0)

            self._body_event.clear()

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

        if end_stream:
            self.stream_id += 2
            self._valid_req_num += 1

    def send_ping(self, data: bytes = b"\x00\x01\x02\x03\x04\x05\x06\x07") -> None:
        self.h2_connection.ping(opaque_data=data)
        self.send_bytes(self.h2_connection.data_to_send())
        self.h2_connection.clear_outbound_data_buffer()

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
        self._ack_settings = False

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

    def send_reset_stream(self, stream_id: int, error_code: int = 0) -> None:
        self.h2_connection.reset_stream(stream_id, error_code)
        self.send_bytes(data=self.h2_connection.data_to_send())

    def send_goaway(self, error_code: int = 0, last_stream_id: int | None = None) -> None:
        self.h2_connection.close_connection(error_code=error_code, last_stream_id=last_stream_id)
        self.send_bytes(data=self.h2_connection.data_to_send())

    async def wait_for_ack_settings(self, timeout: float = 5, msg: Optional[str] = None) -> None:
        """Wait SETTINGS frame with ack flag."""
        timeout_not_exceeded = await util.wait_until(
            lambda: not self._ack_settings,
            timeout,
            abort_cond=lambda: self.connection_is_closed and not self._connecting,
        )

        assert timeout_not_exceeded, f"{timeout_not_exceeded} is not True." + (
            msg or f"Timeout exceeded while waiting ACK in SETTINGS frame: {timeout}"
        )

    async def wait_for_reset_stream(
        self, stream_id: int, timeout: float = 5, msg: Optional[str] = None
    ) -> None:
        """Wait RST_STREAM frame for stream."""
        timeout_not_exceeded = await util.wait_until(
            lambda: not self.h2_connection._stream_is_closed_by_reset(stream_id=stream_id),
            timeout,
            abort_cond=lambda: self.connection_is_closed and not self._connecting,
        )

        assert timeout_not_exceeded, f"{timeout_not_exceeded} is not True." + (
            msg
            or f"Timeout exceeded while waiting RST_STREAM frame for stream_id={stream_id}: {timeout}"
        )

    async def wait_for_headers_frame(
        self, stream_id: int, timeout: float = 5, msg: Optional[str] = None
    ) -> None:
        """Wait HEADERS frame for stream."""
        stream: h2.connection.H2Stream = self.h2_connection._get_stream_by_id(stream_id=stream_id)
        timeout_not_exceeded = await util.wait_until(
            lambda: not stream.state_machine.headers_received,
            timeout,
            abort_cond=lambda: self.connection_is_closed and not self._connecting,
        )

        assert timeout_not_exceeded, f"{timeout_not_exceeded} is not True." + (
            msg
            or f"Timeout exceeded while waiting HEADERS frame for stream_id={stream_id}: timeout={timeout}"
        )

    async def wait_for_ping_frames(
        self, ping_count: int, timeout: float = 5, msg: Optional[str] = None
    ) -> None:
        timeout_not_exceeded = await util.wait_until(
            lambda: self._ping_received < ping_count,
            timeout,
            abort_cond=lambda: self.connection_is_closed and not self._connecting,
        )

        assert timeout_not_exceeded, f"{timeout_not_exceeded} is not True." + (
            msg or f"Timeout exceeded while waiting {ping_count} PING frames: {timeout}"
        )

    @property
    def response_sequence(self) -> list[int]:
        return self._response_sequence

    @property
    def auto_flow_control(self) -> bool:
        return self._auto_flow_control

    @auto_flow_control.setter
    def auto_flow_control(self, auto_flow_control: bool) -> None:
        self._auto_flow_control = auto_flow_control

    @property
    def last_stream_id(self) -> int:
        return self._last_stream_id

    @property
    def ping_received(self) -> int:
        return self._ping_received

    @property
    def req_body_buffers(self) -> List[ReqBodyBuffer]:
        return self._req_body_buffers

    @property
    def ack_settings(self) -> bool:
        return self._ack_settings

    @property
    def last_response_buffer(self) -> bytes:
        return self._last_response_buffer

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

    def _process_received_data(self, data: bytearray) -> Optional[int]:
        if self._clear_last_response_buffer:
            self._clear_last_response_buffer = False
            self._last_response_buffer = bytes()

        self._last_response_buffer += data

        events = self.h2_connection.receive_data(bytes(data))

        self._http_logger.info("Receive 'h2_connection' events")
        self._http_logger.debug(f"{events}")
        for event in events:
            if isinstance(event, ResponseReceived):
                # H2Connection returns ResponseReceived event when HEADERS and
                # all CONTINUATION frames with END_HEADERS flag are received.
                headers = self.__binary_headers_to_string(event.headers)
                try:
                    response = deproxy_message.H2Response(
                        headers + "\r\n", method="", body_parsing=False
                    )

                    self._active_responses[event.stream_id] = response
                except deproxy_message.IncompleteMessage:
                    self._http_logger.debug(f"Receive IncompleteMessage")
                except deproxy_message.ParseError as e:
                    self._http_logger.error(
                        f"Can't parse message\n<<<<\n{self.response_buffer}\n>>>>", exc_info=True
                    )
                    raise
            elif isinstance(event, DataReceived):
                body = event.data.decode()
                response = self._active_responses.get(event.stream_id)
                response.body += body
                if self.auto_flow_control:
                    self.increment_flow_control_window(
                        event.stream_id, event.flow_controlled_length
                    )
            elif isinstance(event, TrailersReceived):
                response = self._active_responses.get(event.stream_id)
                for trailer in event.headers:
                    response.trailer.add(trailer[0].decode(), trailer[1].decode())
            elif isinstance(event, StreamEnded):
                response = self._active_responses.pop(event.stream_id, None)
                if response is None:
                    continue
                self._response_sequence.append(event.stream_id)
                self._receive_response(response)
                self._nrresp += 1
            elif isinstance(event, StreamReset):
                # the client don't receive a response for RST_STREAM, so we should decrease a counter
                self._valid_req_num -= 1
                self._add_error_code(event.error_code)
            elif isinstance(event, ConnectionTerminated):
                self._add_error_code(event.error_code)
                self._last_stream_id = event.last_stream_id
            elif isinstance(event, SettingsAcknowledged):
                self._ack_settings = True
                self._ack_cnt += 1
            elif isinstance(event, WindowUpdated):
                self._body_event.set()
            elif isinstance(event, PingAckReceived):
                self._ping_received += 1

        return len(data)

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

    def __prepare_data_frames(
        self, body: bytes, end_stream: bool, stream_id: int
    ) -> tuple[bytes, int]:
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
        self._body_event.set()

    def _add_to_request_buffers(
        self,
        *,
        data,
        end_stream: bool = None,
        priority_weight=None,
        priority_depends_on=None,
        priority_exclusive=None,
    ) -> None:
        if isinstance(data, str):
            # in case when you use `make_request` to sending body
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
            self._add_to_requests_queue(data=self.h2_connection.data_to_send())
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
            self._add_to_requests_queue(data=self.h2_connection.data_to_send())

        if self._deproxy_auto_parser.parsing and end_stream and isinstance(data, (tuple, list)):
            self._deproxy_auto_parser.prepare_expected_request(
                self._deproxy_auto_parser.create_request_from_list_or_tuple(data), client=self
            )

    def __calculate_frame_length(self, pos):
        #: The type byte defined for CONTINUATION frames.
        continuation_type = 0x09

        frame_type = self._last_response_buffer[pos + 3]
        if frame_type != continuation_type:
            return -1
        # TCP/IP use big endian
        return int.from_bytes(self._last_response_buffer[pos : pos + 3], "big")

    def clear_stats(self):
        super().clear_stats()
        self.h2_connection: Optional[h2.connection.H2Connection] = None
        self.stream_id: int = 1
        self._active_responses = {}
        self._ack_settings: bool = False
        self._last_stream_id: Optional[int] = None
        self._last_response_buffer = bytes()
        self._clear_last_response_buffer: bool = False
        self._response_sequence = []
        self._req_body_buffers: List[ReqBodyBuffer] = list()
        self._auto_flow_control = True
        self._ping_received = 0
        self._ack_cnt = 0

    def check_header_presence_in_last_response_buffer(self, header: bytes) -> bool:
        if len(header) == 0:
            return True
        if len(header) > len(self._last_response_buffer):
            return False
        for bpos in range(0, len(self._last_response_buffer) - len(header) + 1):
            if self._last_response_buffer[bpos] == header[0]:
                equal = True
                hpos = 0
                skip = 0
                while hpos < len(header):
                    if self._last_response_buffer[bpos + hpos + skip] != header[hpos]:
                        part_len = self.__calculate_frame_length(bpos + hpos + skip)
                        if part_len < 0:
                            equal = False
                            break
                        if part_len > len(header) - hpos:
                            part_len = len(header) - hpos
                        # Skip frame size
                        skip += 9
                        for t in range(0, part_len):
                            if self._last_response_buffer[bpos + hpos + skip] != header[hpos]:
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
