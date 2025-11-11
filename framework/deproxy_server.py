import asyncore
import socket
import sys
import time
from typing import Optional

import run_config
from framework import stateful
from framework.deproxy_base import BaseDeproxy
from helpers import deproxy, error, tempesta, tf_cfg, util

dbg = deproxy.dbg

from helpers.util import fill_template

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class ServerConnection(asyncore.dispatcher):
    def __init__(self, *, server: "StaticDeproxyServer", sock: socket.socket):
        super().__init__(sock=sock)
        self._server = server
        self._last_segment_time: int = 0
        self._responses_done: int = 0
        self._request_buffer: str = ""
        self._response_buffer: list[bytes] = []

        self._cur_pipelined = 0
        self._cur_responses_list = []
        self.__time_to_send: float = 0
        self.__new_response: bool = True
        self.nrreq: int = 0
        if self._server.send_after_conn_established:
            self._add_response_to_sending_buffer(self._server.response)

        dbg(self, 6, "New server connection", prefix="\t")

    def _add_response_to_sending_buffer(self, response: bytes) -> None:
        dbg(self, 4, "Send response:", prefix="\t")
        tf_cfg.dbg(5, response)

        self._cur_responses_list.append(response)
        self.flush()

    def sleep(self) -> None:
        """
        Stops server responding. Required in the cases when the server have
        to respond with the some delay
        """
        self.__time_to_send = time.time() + self._server.delay_before_sending_response

    def is_sleeping(self) -> bool:
        """
        Return true in server does not responding now and waiting for
        some delay
        """
        if not self._server.delay_before_sending_response:
            return False

        if not self.__time_to_send:
            return False

        return self.__time_to_send > time.time()

    def flush(self):
        self._response_buffer.append(b"".join(self._cur_responses_list))
        self._cur_pipelined = 0
        self._cur_responses_list = []

    def writable(self):
        if self.is_sleeping():
            return False

        if (
            self._server.segment_gap != 0
            and time.time() - self._last_segment_time < self._server.segment_gap / 1000.0
        ):
            return False
        return (not self.connected) or len(self._response_buffer) > self._responses_done

    def handle_error(self):
        _, v, _ = sys.exc_info()
        error.bug("\tDeproxy: SrvConnection: %s" % v)

    def handle_close(self):
        dbg(self, 6, "Close connection", prefix="\t")
        self.close()
        if self._server and self in self._server.connections:
            self._server.remove_connection(connection=self)

    def handle_read(self):
        self._request_buffer += self.recv(deproxy.MAX_MESSAGE_SIZE).decode()

        dbg(self, 4, "Receive data:", prefix="\t")
        tf_cfg.dbg(5, self._request_buffer)

        while self._request_buffer:
            try:
                request = deproxy.Request(self._request_buffer)
                self.nrreq += 1
            except deproxy.IncompleteMessage:
                return None
            except deproxy.ParseError as e:
                dbg(
                    self,
                    4,
                    ("Can't parse message\n" "<<<<<\n%s>>>>>" % self._request_buffer),
                )
                return None

            dbg(self, 4, "Receive request:", prefix="\t")
            tf_cfg.dbg(5, request)
            response, need_close = self._server.receive_request(request)
            if self._server.drop_conn_when_request_received:
                self.handle_close()
            if response:
                dbg(self, 4, "Send response:", prefix="\t")
                tf_cfg.dbg(5, response)
                self._cur_responses_list.append(response)
                self._cur_pipelined += 1
                if self._cur_pipelined >= self._server.pipelined:
                    self.flush()

            if need_close:
                self.close()
            self._request_buffer = self._request_buffer[len(request.msg) :]
        # Handler will be called even if buffer is empty.
        else:
            return None

    def handle_write(self):
        if self._server.delay_before_sending_response and self.__new_response:
            self.__new_response = False
            return self.sleep()

        if run_config.TCP_SEGMENTATION and self._server.segment_size == 0:
            self._server.segment_size = run_config.TCP_SEGMENTATION

        segment_size = (
            self._server.segment_size if self._server.segment_size else deproxy.MAX_MESSAGE_SIZE
        )

        resp = self._response_buffer[self._responses_done]
        sent = self.socket.send(resp[:segment_size])

        if sent < 0:
            return

        self._response_buffer[self._responses_done] = resp[sent:]

        self._last_segment_time = time.time()
        if self._response_buffer[self._responses_done] == b"":
            self._responses_done += 1
            self.__new_response = True

        if self._responses_done == self._server.keep_alive and self._server.keep_alive:
            self.handle_close()


class StaticDeproxyServer(BaseDeproxy):
    def __init__(
        self,
        # BaseDeproxy
        *,
        deproxy_auto_parser,
        port: int,
        bind_addr: Optional[str],
        segment_size: int,
        segment_gap: int,
        is_ipv6: bool,
        # StaticDeproxyServer
        response: str | bytes | deproxy.Response,
        keep_alive: int,
        drop_conn_when_request_received: bool,
        send_after_conn_established: bool,
        delay_before_sending_response: float,
        hang_on_req_num: int,
        pipelined: int,
    ):
        # Initialize the `BaseDeproxy`
        super().__init__(
            deproxy_auto_parser=deproxy_auto_parser,
            port=port,
            bind_addr=bind_addr,
            segment_size=segment_size,
            segment_gap=segment_gap,
            is_ipv6=is_ipv6,
        )

        self._reinit_variables()
        self.response = response
        self.conns_n = tempesta.server_conns_default()
        self.keep_alive = keep_alive
        self.drop_conn_when_request_received = drop_conn_when_request_received
        self.send_after_conn_established = send_after_conn_established
        self.delay_before_sending_response = delay_before_sending_response
        self.hang_on_req_num = hang_on_req_num
        self.pipelined = pipelined

    def _reinit_variables(self):
        self._connections: list[ServerConnection] = list()
        self._requests: list[deproxy.Request] = list()

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, _ = pair
            if self.segment_size:
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            handler = ServerConnection(server=self, sock=sock)
            self._connections.append(handler)
            # ATTENTION
            # Due to the polling cycle, creating new connection can be
            # performed before removing old connection.
            # So we can have case with > expected amount of connections
            # It's not a error case, it's a problem of polling

    def handle_error(self):
        type_, v, _ = sys.exc_info()
        self.handle_close()
        raise v

    def handle_close(self):
        self.close()
        self.state = stateful.STATE_STOPPED

    def reset_new_connections(self) -> None:
        """
        Close the server socket.
        This method should not be used to stop the server
        because the existing connections will be work.
        """
        self.close()

    def _run_deproxy(self):
        self.create_socket(socket.AF_INET6 if self.is_ipv6 else socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((self.bind_addr, self.port))
        self.listen(socket.SOMAXCONN)

    def _stop_deproxy(self):
        self.close()
        connections = [conn for conn in self._connections]
        for conn in connections:
            conn.handle_close()

    def wait_for_connections(self, timeout=1):
        if self.state != stateful.STATE_STARTED:
            return False

        return util.wait_until(
            lambda: len(self._connections) < self.conns_n, timeout, poll_freq=0.001
        )

    def flush(self):
        for conn in self._connections:
            conn.flush()

    @property
    def response(self) -> bytes:
        return self.__response

    @response.setter
    def response(self, response: str | bytes | deproxy.Response) -> None:
        self.set_response(response)

    def set_response(self, response: str | bytes | deproxy.Response) -> None:
        if isinstance(response, str):
            self.__response = response.encode()
        elif isinstance(response, bytes):
            self.__response = response
        elif isinstance(response, deproxy.Response):
            self.__response = response.msg.encode()

    @property
    def conns_n(self) -> int:
        return self._conns_n

    @conns_n.setter
    def conns_n(self, conns_n: int) -> None:
        if conns_n < 0:
            raise ValueError("`conns_n` MUST be greater than or equal to 0.")
        self._conns_n = conns_n

    @property
    def last_request(self) -> Optional[deproxy.Request]:
        if not self.requests:
            return None
        return self.requests[-1]

    @property
    def requests(self) -> list[deproxy.Request]:
        return self._requests

    @property
    def connections(self) -> list[ServerConnection]:
        return self._connections

    def remove_connection(self, connection: ServerConnection) -> None:
        self._connections.remove(connection)

    def receive_request(self, request: deproxy.Request) -> (bytes, bool):
        self._requests.append(request)
        req_num = len(self.requests)

        # Don't send response to this request w/o disconnect
        if 0 < self.hang_on_req_num <= req_num:
            return "", True

        if self._deproxy_auto_parser.parsing:
            self._deproxy_auto_parser.check_expected_request(self.last_request)
            # Server sets expected response after receiving a request
            self._deproxy_auto_parser.prepare_expected_response(self.__response)

        return self.__response, False

    def wait_for_requests(self, n: int, timeout=10, strict=False, adjust_timeout=False) -> bool:
        """wait for the `n` number of responses to be received"""
        timeout_not_exceeded = util.wait_until(
            lambda: len(self.requests) < n,
            timeout=timeout,
            abort_cond=lambda: self.state != stateful.STATE_STARTED,
            adjust_timeout=adjust_timeout,
        )
        if strict:
            assert (
                timeout_not_exceeded != False
            ), f"Timeout exceeded while waiting connection close: {timeout}"
        return timeout_not_exceeded


def deproxy_srv_factory(server: dict, name, tester):
    is_ipv6 = server.get("is_ipv6", False)
    srv = StaticDeproxyServer(
        # BaseDeproxy
        deproxy_auto_parser=tester._deproxy_auto_parser,
        port=int(server["port"]),
        bind_addr=tf_cfg.cfg.get("Server", "ipv6" if is_ipv6 else "ip"),
        segment_size=server.get("segment_size", 0),
        segment_gap=server.get("segment_gap", 0),
        is_ipv6=is_ipv6,
        # StaticDeproxyServer
        response=fill_template(server.get("response_content", ""), server),
        keep_alive=server.get("keep_alive", 0),
        drop_conn_when_request_received=server.get("drop_conn_when_request_received", False),
        send_after_conn_established=server.get("send_after_conn_established", False),
        delay_before_sending_response=server.get("delay_before_sending_response", 0.0),
        hang_on_req_num=server.get("hang_on_req_num", 0),
        pipelined=server.get("pipelined", 0),
    )

    tester.deproxy_manager.add_server(srv)
    return srv
