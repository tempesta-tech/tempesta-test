__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

import asyncio
import logging
import socket
import typing
from typing import Optional

import run_config
from framework.deproxy import deproxy_message
from framework.deproxy.deproxy_message import IncompleteMessage, ParseError, Request
from framework.helpers import tf_cfg, util
from framework.helpers.util import fill_template
from framework.services import base_server, stateful, tempesta


class ServerConnection:

    def __init__(
        self,
        server: "StaticDeproxyServer",
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        self._server: StaticDeproxyServer = server
        self._reader: asyncio.StreamReader = reader
        self._writer: asyncio.StreamWriter = writer
        self._response_buffer: bytes = b""
        self._responses_done: int = 0
        self._write_func = None
        self.update_segment_size()

        peername = writer.get_extra_info("peername")
        self._dst_ip, self._dst_port = peername[0], peername[1]
        _id = f"{self.__class__.__name__}({self._dst_ip}:{self._dst_port})"
        self._tcp_logger = logging.LoggerAdapter(
            logging.getLogger("tcp"), extra={"service": f"{_id}"}
        )
        self._http_logger = logging.LoggerAdapter(
            logging.getLogger("http"), extra={"service": f"{_id}"}
        )

        self._cur_pipelined: int = 0
        self._cur_responses_list: list[bytes] = list()

        if self._server.send_after_conn_established:
            self._add_response_to_sending_buffer()
            self.flush()

        self._tcp_logger.debug("New server connection")

    def update_segment_size(self) -> None:
        if self._server.segment_size:
            self._write_func = self._send_bytes_with_tcp_segmentation
        else:
            self._write_func = self._send_bytes

    def close(self) -> None:
        self._writer.close()
        if self._server and self in self._server.connections:
            self._server.remove_connection(connection=self)

    def flush(self):
        self._response_buffer += b"".join(self._cur_responses_list)
        self._cur_pipelined = 0
        self._responses_done += len(self._cur_responses_list)
        self._cur_responses_list = []

    def _add_response_to_sending_buffer(self) -> None:
        self._cur_responses_list.append(self._server.response)
        self._cur_pipelined += 1

    async def _send_bytes_with_tcp_segmentation(self) -> None:
        data_to_send = self._response_buffer[: self._server.segment_size]
        self._writer.write(data_to_send)
        await self._writer.drain()
        self._response_buffer = self._response_buffer[self._server.segment_size :]
        self._tcp_logger.info(
            f"{len(data_to_send)} bytes sent. {len(self._response_buffer)} bytes left."
        )

    async def _send_bytes(self) -> None:
        self._writer.write(self._response_buffer)
        await self._writer.drain()
        self._response_buffer = b""
        self._http_logger.info(
            f"A response was send. The current number of a response - {self._responses_done}"
        )

    async def _read_loop(self):
        req_buffer = b""
        while True:
            req_buffer += await self._reader.read(1024 * 64)
            while req_buffer:
                try:
                    request = Request(req_buffer.decode())
                except IncompleteMessage:
                    break
                except ParseError:
                    self._http_logger.error(
                        f"Can't parse message\n<<<<<\n{req_buffer}>>>>>", exc_info=True
                    )
                    break

                self._http_logger.info("Receive request")
                self._http_logger.debug(request)

                self._http_logger.info(f"A request is received.")
                need_response, need_close = self._server._receive_request(request, self)

                if self._server.drop_conn_when_request_received:
                    self.close()
                    break

                if need_response:
                    self._add_response_to_sending_buffer()
                    if self._cur_pipelined >= self._server.pipelined:
                        self.flush()

                if need_close:
                    self.close()
                req_buffer = req_buffer[len(request.msg) :]

            await asyncio.sleep(run_config.asyncio_freq)

    async def _write_loop(self):
        while True:
            if self._response_buffer:
                await asyncio.sleep(self._server.delay_before_sending_response)

                await self._write_func()

                if self._responses_done == self._server.keep_alive and self._server.keep_alive:
                    self.close()
            await asyncio.sleep(self._server.segment_gap or run_config.asyncio_freq)


class StaticDeproxyServer(base_server.BaseServer):
    _connection_factory = ServerConnection

    def __init__(
        self,
        # BaseDeproxy
        *,
        id_: str,
        deproxy_auto_parser,
        port: int,
        bind_addr: Optional[str],
        segment_size: int,
        segment_gap: int,
        is_ipv6: bool,
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

        self.port = port
        self.bind_addr = bind_addr
        super().__init__(id_=id_)
        self._tcp_logger = logging.LoggerAdapter(
            logging.getLogger("tcp"), extra={"service": f"{self}"}
        )
        self._http_logger = logging.LoggerAdapter(
            logging.getLogger("http"), extra={"service": f"{self}"}
        )
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
        self._accepting = False

    def __str__(self):
        return f"{self.__class__.__name__}({self.bind_addr}:{self.port})"

    def clear_stats(self):
        super().clear_stats()
        self._connections: list[ServerConnection] = list()
        self._requests: list[deproxy_message.Request] = list()
        self.response = self._default_response

    def reset_new_connections(self) -> None:
        """
        Close the server socket.
        This method should not be used to stop the server
        because the existing connections will be work.
        """
        self._server.close()

    def _stop_procedures(self) -> list[typing.Callable]:
        return [self._stop_deproxy]

    async def run_start(self):
        self._server = await asyncio.start_server(
            client_connected_cb=self._accept_connection,
            host=self.bind_addr,
            port=self.port,
            family=socket.AF_INET6 if self.is_ipv6 else socket.AF_INET,
            reuse_address=True,
        )
        self._server_task = asyncio.create_task(self._server.serve_forever())

    async def _stop_deproxy(self):
        self._accepting = False
        self._server.close()
        for conn in self._connections[:]:
            conn.close()
        await self._server.wait_closed()
        self._server_task.cancel()

    def _wait_for_connections(self) -> bool:
        return len(self._connections) < self.conns_n

    async def wait_for_connections_closed(self, timeout=1):
        if self.state != stateful.STATE_STARTED:
            return False
        return await util.wait_until(lambda: len(self._connections) != 0, timeout)

    def flush(self):
        for conn in self._connections:
            conn.flush()

    async def _accept_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._accepting = True
        conn = self._connection_factory(self, reader, writer)
        self._connections.append(conn)
        await asyncio.gather(conn._read_loop(), conn._write_loop())

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

    def _receive_request(self, request: Request, connection: ServerConnection) -> tuple[bool, bool]:
        """
        Return two flags (need_response, need_close)
        """
        self._requests.append(request)
        req_num = len(self._requests)
        self._http_logger.info(f"The current number of requests - {req_num}")

        # Don't send response to this request w/o disconnect
        if 0 < self.hang_on_req_num <= req_num:
            return False, True

        if self._deproxy_auto_parser.parsing:
            self._deproxy_auto_parser.check_expected_request(request)
            # Server sets expected response after receiving a request
            self._deproxy_auto_parser.prepare_expected_response(self.response)

        return True, False

    async def wait_for_requests(
        self, n: int, timeout=10, strict=False, adjust_timeout=False
    ) -> bool:
        """wait for the `n` number of responses to be received"""
        timeout_not_exceeded = await util.wait_until(
            lambda: len(self.requests) < n,
            timeout=timeout,
            abort_cond=lambda: not self._accepting,
            adjust_timeout=adjust_timeout,
        )
        if strict:
            assert (
                timeout_not_exceeded != False
            ), f"Timeout exceeded while waiting connection close: {timeout}"
        return timeout_not_exceeded


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
    )
    return srv


def deproxy_srv_factory(server: dict, name, tester):
    return deproxy_srv_initializer(server, name, tester)
