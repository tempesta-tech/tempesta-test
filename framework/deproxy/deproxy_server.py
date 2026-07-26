__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

import asyncio
import logging
import socket
import typing
from typing import Awaitable, Callable, Optional

import run_config
from framework.deproxy import deproxy_message
from framework.helpers import tf_cfg, util
from framework.helpers.util import fill_template
from framework.services import base_server, stateful


class ServerConnection:

    def __init__(
        self,
        server: "StaticDeproxyServer",
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        self.addr = writer.get_extra_info("peername")
        self._id = f"{self.__class__.__name__}({self.addr[0]}:{self.addr[1]})"
        self._tcp_logger = logging.LoggerAdapter(
            logging.getLogger("tcp"), extra={"service": f"{self._id}"}
        )
        self._http_logger = logging.LoggerAdapter(
            logging.getLogger("http"), extra={"service": f"{self._id}"}
        )

        self._server: StaticDeproxyServer = server
        self._reader: asyncio.StreamReader = reader
        self._writer: asyncio.StreamWriter = writer

        self._read_task: asyncio.Task = asyncio.create_task(self._read_loop())
        self._write_task: asyncio.Task = asyncio.create_task(self._write_loop())
        self._readwrite = asyncio.Event()
        self._readwrite.set()
        self._queue: asyncio.Queue[tuple[bytes, int] | None] = asyncio.Queue()
        self._write_func: Callable[[bytes], Awaitable[None]] = None

        self._responses_done: int = 0
        self.update_segment_size()

        self.nrreq = 0
        self._cur_pipelined = 0
        self._cur_responses_list = []

        if self._server.send_after_conn_established:
            self._add_response_to_sending_buffer(self._server.response)
            self.flush()

        self._tcp_logger.debug("New server connection")

    def _add_response_to_sending_buffer(self, response: bytes) -> None:
        self._tcp_logger.debug("Receive request")
        self._tcp_logger.debug(response)

        self._cur_responses_list.append(response)
        self._cur_pipelined += 1

    async def disable_readable(self) -> None:
        if not self._read_task.done():
            self._read_task.cancel()
            try:
                await self._read_task
            except asyncio.CancelledError:
                ...

    def enable_readable(self) -> None:
        if not self._read_task.cancelled():
            raise Exception("Call disable_readable first.")
        self._read_task: asyncio.Task = asyncio.create_task(self._read_loop())

    def update_segment_size(self) -> None:
        self._write_func = (
            self._send_bytes_with_tcp_segmentation
            if self._server.segment_size
            else self._send_bytes
        )

    async def close(self) -> None:
        if not self._readwrite.is_set():
            return
        self._readwrite.clear()

        self._queue.put_nowait(None)
        try:
            self._writer.close()
            await self._writer.wait_closed()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            if self in self._server.connections:
                self._server.remove_connection(connection=self)

    def flush(self):
        self._queue.put_nowait((b"".join(self._cur_responses_list), self._cur_pipelined))
        self._cur_pipelined = 0
        self._cur_responses_list = []

    async def _send_bytes_with_tcp_segmentation(self, data: bytes) -> None:
        initial_len = len(data)
        if initial_len == 0:
            return

        seg_size = self._server.segment_size
        seg_gap = self._server.segment_gap

        view = memoryview(data)
        offset = 0

        while offset < initial_len:
            data_to_send = view[offset : offset + seg_size]
            self._writer.write(data_to_send)
            await self._writer.drain()

            offset += seg_size

            if seg_gap:
                await asyncio.sleep(seg_gap)

        self._tcp_logger.info(f"Segmented transfer finished. Total size: {initial_len} bytes.")

    async def _send_bytes(self, data: bytes) -> None:
        if len(data) == 0:
            return
        self._writer.write(data)
        await self._writer.drain()
        self._http_logger.info(
            f"A response was sent. The current number of responses - {self._responses_done}"
        )

    @staticmethod
    def __safe_readwrite(func):
        async def wrapper(self: "ServerConnection"):
            try:
                await func(self)
            except (BrokenPipeError, ConnectionResetError):
                self._tcp_logger.info("Close TCP connection from the remote side.")
                await self.close()

        return wrapper

    @__safe_readwrite
    async def _read_loop(self):
        req_buffer = bytearray()
        while self._readwrite.is_set():
            data = await self._reader.read(deproxy_message.MAX_MESSAGE_SIZE)
            if not data:
                await self.close()
                return
            req_buffer.extend(data)

            while req_buffer:
                try:
                    request = deproxy_message.Request(req_buffer.decode("utf-8", errors="ignore"))
                    self.nrreq += 1
                except deproxy_message.IncompleteMessage:
                    break
                except deproxy_message.ParseError:
                    self._http_logger.error(
                        f"Can't parse message\n<<<<<\n{req_buffer}>>>>>", exc_info=True
                    )
                    break

                self._http_logger.info("Receive request")
                self._http_logger.debug(request)

                self._http_logger.info(f"A request is received.")
                response, need_close = self._server._receive_request(request, self)

                if self._server.drop_conn_when_request_received:
                    await self.close()
                    break

                if response:
                    self._add_response_to_sending_buffer(response)
                    if self._cur_pipelined >= self._server.pipelined:
                        self.flush()

                if need_close:
                    self.flush()
                    await self.close()
                    break

                del req_buffer[: request.original_length]

    @__safe_readwrite
    async def _write_loop(self) -> None:
        while self._readwrite.is_set():
            item = await self._queue.get()

            if item is None:
                self._queue.task_done()
                break

            if self._server.delay_before_sending_response:
                await asyncio.sleep(self._server.delay_before_sending_response)

            data, count = item
            await self._write_func(data)
            self._responses_done += count
            self._queue.task_done()

            if self._server.keep_alive and self._responses_done >= self._server.keep_alive:
                await self.close()
                break


class StaticDeproxyServer(base_server.BaseServer):
    _connection_factory = ServerConnection

    def __init__(
        self,
        *,
        id_: str,
        deproxy_auto_parser,
        port: int,
        bind_addr: Optional[str],
        segment_size: int,
        segment_gap: int,
        is_ipv6: bool,
        response: str | bytes | deproxy_message.Response,
        keep_alive: int,
        drop_conn_when_request_received: bool,
        send_after_conn_established: bool,
        delay_before_sending_response: float,
        hang_on_req_num: int,
        pipelined: int,
        rcv_buf_size: int,
    ):
        # this variable is needed for tests with common response for all tests in one class.
        self._default_response = response

        self.__request_event = asyncio.Event()
        self.__connection_event = asyncio.Event()

        self.port = port
        self.bind_addr = bind_addr
        self._tcp_logger = logging.LoggerAdapter(
            logging.getLogger("tcp"), extra={"service": f"{self}"}
        )
        self._http_logger = logging.LoggerAdapter(
            logging.getLogger("http"), extra={"service": f"{self}"}
        )
        super().__init__(id_=id_)
        self._server = None
        self._deproxy_auto_parser = deproxy_auto_parser
        self.is_ipv6 = is_ipv6
        self.segment_size = segment_size or run_config.TCP_SEGMENTATION or 0
        self.segment_gap = segment_gap
        self.keep_alive = keep_alive
        self.drop_conn_when_request_received = drop_conn_when_request_received
        self.send_after_conn_established = send_after_conn_established
        self.delay_before_sending_response = delay_before_sending_response
        self.hang_on_req_num = hang_on_req_num
        self.pipelined = pipelined
        self.rcv_buf_size = rcv_buf_size

    def __str__(self):
        return f"{self.__class__.__name__}({self.bind_addr}:{self.port})"

    def clear_stats(self):
        super().clear_stats()
        self._connections: list[ServerConnection] = list()
        self._requests: list[deproxy_message.Request] = list()
        self.response = self._default_response

        self.__request_event.clear()
        self.__connection_event.clear()

    async def _accept_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        if self.rcv_buf_size:
            writer.get_extra_info("socket").setsockopt(
                socket.SOL_SOCKET, socket.SO_RCVBUF, self.rcv_buf_size
            )
        conn = self._connection_factory(self, reader, writer)
        self._connections.append(conn)
        self.__connection_event.set()

    def reset_new_connections(self) -> None:
        """
        Close the server socket.
        This method should not be used to stop the server
        because the existing connections will be work.
        """
        self._server.close()

    def _stop_procedures(self) -> list[typing.Callable]:
        return [self._stop_deproxy]

    async def run_start(self) -> None:
        self._server = await asyncio.start_server(
            client_connected_cb=self._accept_connection,
            host=self.bind_addr,
            port=self.port,
            family=socket.AF_INET6 if self.is_ipv6 else socket.AF_INET,
            reuse_address=True,
        )

    async def _stop_deproxy(self) -> None:
        self._server.close()
        await asyncio.gather(*(conn.close() for conn in self._connections[:]))
        await self._server.wait_closed()
        self.clear_stats()

    def _wait_for_connections(self) -> bool:
        return len(self._connections) < self.conns_n

    async def wait_for_connections_closed(
        self, timeout: float = 1.0, msg: Optional[str] = None
    ) -> None:
        if self.state != stateful.STATE_STARTED:
            raise AssertionError(f"The {self} server is not started.")
        timeout_not_exceeded = await util.wait_until_event(
            lambda: len(self._connections) != 0,
            event=self.__connection_event,
            timeout=timeout,
            abort_cond=lambda: self.state != stateful.STATE_STARTED,
        )

        assert timeout_not_exceeded, f"{timeout_not_exceeded} is not True." + (
            msg
            or f"The server connections are not closed. The current connections N - {len(self.connections)}."
        )

    def flush(self):
        for conn in self._connections:
            conn.flush()

    @property
    def segment_size(self) -> int:
        return self._segment_size

    @segment_size.setter
    def segment_size(self, segment_size: int) -> None:
        if segment_size < 0:
            raise ValueError("`segment_size` MUST be greater than or equal to 0.")
        self._segment_size = segment_size
        for conn in self.connections:
            conn.update_segment_size()

    @property
    def response(self) -> bytes:
        return self.__response

    @response.setter
    def response(self, response: str | bytes | deproxy_message.Response) -> None:
        self.set_response(response)

    def set_response(self, response: str | bytes | deproxy_message.Response) -> None:
        if isinstance(response, str):
            self.__response = response.encode()
        elif isinstance(response, bytes):
            self.__response = response
        elif isinstance(response, deproxy_message.Response):
            self.__response = response.msg.encode()

        if self.__response and len(self.__response.decode(errors="ignore")) < 1024:
            self._http_logger.info(f"Set response:\n{self.__response.decode(errors='ignore')}")

    @property
    def last_request(self) -> Optional[deproxy_message.Request]:
        if not self.requests:
            return None
        return self.requests[-1]

    @property
    def requests(self) -> list[deproxy_message.Request]:
        return self._requests

    @property
    def connections(self) -> list[ServerConnection]:
        return self._connections

    def remove_connection(self, connection: ServerConnection) -> None:
        self._connections.remove(connection)
        self.__connection_event.set()

    def _receive_request(
        self, request: deproxy_message.Request, connection: ServerConnection
    ) -> tuple[bytes, bool]:
        self._requests.append(request)
        self.__request_event.set()
        req_num = len(self.requests)
        self._http_logger.info(f"A request was receive. The current number of requests - {req_num}")

        # Don't send response to this request w/o disconnect
        if 0 < self.hang_on_req_num <= req_num:
            return "", True

        if self._deproxy_auto_parser.parsing:
            self._deproxy_auto_parser.check_expected_request(self.last_request)
            # Server sets expected response after receiving a request
            self._deproxy_auto_parser.prepare_expected_response(self.__response)

        return self.__response, False

    async def wait_for_requests(
        self, n: int, timeout: float = 5.0, adjust_timeout: bool = False, msg: Optional[str] = None
    ) -> None:
        """wait for the `n` number of responses to be received"""
        timeout_not_exceeded = await util.wait_until_event(
            lambda: len(self.requests) < n,
            event=self.__request_event,
            timeout=timeout,
            abort_cond=lambda: not self._server.is_serving(),
            adjust_timeout=adjust_timeout,
        )

        assert timeout_not_exceeded, f"{timeout_not_exceeded} is not True." + (
            msg or f"Timeout exceeded while waiting connection close: {timeout}"
        )


def deproxy_srv_initializer(
    server: dict, name: str, tester, default_server_class=StaticDeproxyServer
):
    is_ipv6 = server.get("is_ipv6", False)
    srv = default_server_class(
        id_=name,
        deproxy_auto_parser=tester._deproxy_auto_parser,
        port=int(server["port"]),
        bind_addr=tf_cfg.cfg.get("Server", "ipv6" if is_ipv6 else "ip"),
        segment_size=server.get("segment_size", 0),
        segment_gap=server.get("segment_gap", 0),
        is_ipv6=is_ipv6,
        response=fill_template(server.get("response_content", ""), server),
        keep_alive=server.get("keep_alive", 0),
        drop_conn_when_request_received=server.get("drop_conn_when_request_received", False),
        send_after_conn_established=server.get("send_after_conn_established", False),
        delay_before_sending_response=server.get("delay_before_sending_response", 0.0),
        hang_on_req_num=server.get("hang_on_req_num", 0),
        pipelined=server.get("pipelined", 0),
        rcv_buf_size=server.get("rcv_buf_size", -1),
    )
    return srv


def deproxy_srv_factory(server: dict, name, tester):
    return deproxy_srv_initializer(server, name, tester)
