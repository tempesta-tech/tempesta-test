__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

import asyncio
import socket
from typing import Optional

from framework.deproxy import deproxy_message
from framework.deproxy.deproxy_connection import (
    DeproxyBase,
    DeproxyConnection,
    safe_readwrite,
)
from framework.helpers import tf_cfg, util
from framework.helpers.util import fill_template
from framework.services import base_server, stateful


class ServerConnection(DeproxyConnection):
    _deproxy: "StaticDeproxyServer"

    def __init__(
        self,
        server: "StaticDeproxyServer",
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        super().__init__(server, reader, writer)

        self._responses_done = 0
        self._cur_pipelined = 0
        self._cur_responses_list = []

        self._start_readwrite()

        if self._deproxy.send_after_conn_established:
            self._add_response_to_sending_buffer(self._deproxy.response)
            self.flush()

    def _add_response_to_sending_buffer(self, response: bytes) -> None:
        self._tcp_logger.debug("Receive request")
        self._tcp_logger.debug(response)

        self._cur_responses_list.append(response)
        self._cur_pipelined += 1

    def flush(self):
        self._queue.put_nowait((b"".join(self._cur_responses_list), self._cur_pipelined))
        self._cur_pipelined = 0
        self._cur_responses_list = []

    @safe_readwrite
    async def _read_loop(self) -> None:
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
                except deproxy_message.IncompleteMessage:
                    self._http_logger.debug(f"Receive IncompleteMessage")
                    break
                except deproxy_message.ParseError:
                    self._http_logger.error(
                        f"Can't parse message\n<<<<<\n{req_buffer}>>>>>", exc_info=True
                    )
                    break

                self._http_logger.info("Receive request")
                self._http_logger.debug(request)

                self._http_logger.info(f"A request is received.")
                response, need_close = self._deproxy._receive_request(request, self)

                if self._deproxy.drop_conn_when_request_received:
                    await self.close()
                    break

                if response:
                    self._add_response_to_sending_buffer(response)
                    if self._cur_pipelined >= self._deproxy.pipelined:
                        self.flush()

                if need_close:
                    self.flush()
                    await self.close()
                    break

                del req_buffer[: request.original_length]

    @safe_readwrite
    async def _write_loop(self) -> None:
        while self._readwrite.is_set():
            item = await self._queue.get()

            if item is None:
                self._queue.task_done()
                break

            if self._deproxy.delay_before_sending_response:
                await asyncio.sleep(self._deproxy.delay_before_sending_response)

            data, count = item
            await self._write_func(data)
            self._responses_done += count
            self._queue.task_done()

            if self._deproxy.keep_alive and self._responses_done >= self._deproxy.keep_alive:
                await self.close()
                break

    def _after_close(self) -> None:
        if self in self._deproxy.connections:
            self._deproxy.remove_connection(connection=self)


class StaticDeproxyServer(DeproxyBase, base_server.BaseServer):
    _connection_factory = ServerConnection

    def __init__(
        self,
        *,
        # BaseServer
        id_: str,
        # DeproxyBase
        deproxy_auto_parser,
        port: int,
        bind_addr: Optional[str],
        segment_size: int,
        segment_gap: int,
        is_ipv6: bool,
        rcv_buf_size: int,
        # StaticDeproxyServer
        response: str | bytes | deproxy_message.Response,
        keep_alive: int,
        drop_conn_when_request_received: bool,
        send_after_conn_established: bool,
        delay_before_sending_response: float,
        hang_on_req_num: int,
        pipelined: int,
    ):
        # this variable is needed for tests with common response for all tests in one class.
        self._default_response = response

        DeproxyBase.__init__(
            self,
            deproxy_auto_parser,
            port,
            bind_addr,
            segment_size,
            segment_gap,
            is_ipv6,
            rcv_buf_size,
        )
        base_server.BaseServer.__init__(self, id_)
        self._server = None
        self.keep_alive = keep_alive
        self.drop_conn_when_request_received = drop_conn_when_request_received
        self.send_after_conn_established = send_after_conn_established
        self.delay_before_sending_response = delay_before_sending_response
        self.hang_on_req_num = hang_on_req_num
        self.pipelined = pipelined

    def clear_stats(self):
        super().clear_stats()
        self._connections: list[ServerConnection] = list()
        self._requests: list[deproxy_message.Request] = list()
        self.response = self._default_response

        self._message_event.clear()
        self._connection_event.clear()

    async def _accept_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        conn = self._connection_factory(self, reader, writer)
        self._connections.append(conn)
        self._connection_event.set()

    def reset_new_connections(self) -> None:
        """
        Close the server socket.
        This method should not be used to stop the server
        because the existing connections will be work.
        """
        self._server.close()

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
            event=self._connection_event,
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

    def _receive_request(
        self, request: deproxy_message.Request, connection: ServerConnection
    ) -> tuple[bytes, bool]:
        self._requests.append(request)
        self._message_event.set()
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
            event=self._message_event,
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
