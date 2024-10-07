import asyncore
import copy
import ipaddress
import socket
import sys
import threading
import time

import run_config
from framework import stateful
from framework.deproxy_auto_parser import DeproxyAutoParser
from helpers import deproxy, error, port_checks, remote, tempesta, tf_cfg, util

dbg = deproxy.dbg

from helpers.util import fill_template

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"


class ServerConnection(asyncore.dispatcher):
    def __init__(
        self,
        server: "StaticDeproxyServer",
        drop_conn_when_receiving_data: bool,
        sleep_when_receiving_data: float,
        sock: socket.socket,
        keep_alive: int = 0,
        pipelined: int = 0,
    ):
        super().__init__(sock=sock)
        self._server = server
        self._keep_alive = keep_alive
        self._last_segment_time: int = 0
        self._responses_done: int = 0
        self._request_buffer: str = ""
        self._response_buffer: list[bytes] = []
        self._drop_conn_when_receiving_data = drop_conn_when_receiving_data
        self._sleep_when_receiving_data = sleep_when_receiving_data
        self._pipelined = pipelined
        self._cur_pipelined = 0
        self._cur_responses_list = []
        dbg(self, 6, "New server connection", prefix="\t")

    def flush(self):
        self._response_buffer.append(b"".join(self._cur_responses_list))
        self._cur_pipelined = 0
        self._cur_responses_list = []

    def writable(self):
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

        if self._request_buffer and self._sleep_when_receiving_data:
            time.sleep(self._sleep_when_receiving_data)

        if self._drop_conn_when_receiving_data:
            self.close()

        while self._request_buffer:
            try:
                request = deproxy.Request(
                    self._request_buffer, keep_original_data=self._server.keep_original_data
                )
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
            if response:
                dbg(self, 4, "Send response:", prefix="\t")
                tf_cfg.dbg(5, response)
                self._cur_responses_list.append(response)
                self._cur_pipelined += 1
                if self._cur_pipelined >= self._pipelined:
                    self.flush()

            if need_close:
                self.close()
            self._request_buffer = self._request_buffer[request.original_length :]
        # Handler will be called even if buffer is empty.
        else:
            return None

    def handle_write(self):
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

        if self._responses_done == self._keep_alive and self._keep_alive:
            self.handle_close()


class StaticDeproxyServer(asyncore.dispatcher, stateful.Stateful):
    def __init__(
        self,
        port: int,
        deproxy_auto_parser: DeproxyAutoParser,
        response: str | bytes | deproxy.Response = "",
        ip: str = tf_cfg.cfg.get("Server", "ip"),
        conns_n: int = tempesta.server_conns_default(),
        keep_alive: int = 0,
        segment_size: int = 0,
        segment_gap: int = 0,
        keep_original_data: bool = False,
        drop_conn_when_receiving_data: bool = False,
        sleep_when_receiving_data: float = 0,
        pipelined: int = 0,
    ):
        # Initialize the base `dispatcher`
        asyncore.dispatcher.__init__(self)
        stateful.Stateful.__init__(self)

        self._reinit_variables()
        self._deproxy_auto_parser = deproxy_auto_parser
        self._expected_response: deproxy.Response | None = None
        self.port = port
        self.ip = ip
        self.response = response
        self.conns_n = conns_n
        self.keep_alive = keep_alive
        self.keep_original_data = keep_original_data
        self.drop_conn_when_receiving_data = drop_conn_when_receiving_data
        self.sleep_when_receiving_data = sleep_when_receiving_data
        self._port_checker = port_checks.FreePortsChecker()
        self._pipelined = pipelined

        # Following 2 parameters control heavy chunked testing
        # You can set it programmaticaly or via client config
        # TCP segment size, bytes, 0 for disable, usualy value of 1 is sufficient
        self.segment_size = segment_size
        # Inter-segment gap, ms, 0 for disable.
        # You usualy do not need it; update timeouts if you use it.
        self.segment_gap = segment_gap

        self.stop_procedures: list[callable] = [self.__stop_server]
        self.node: remote.Node = remote.host
        self._polling_lock: threading.Lock | None = None

    def _reinit_variables(self):
        self._connections: list[ServerConnection] = list()
        self._last_request: deproxy.Request | None = None
        self._requests: list[deproxy.Request] = list()

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, _ = pair
            if self.segment_size:
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            handler = ServerConnection(
                server=self,
                drop_conn_when_receiving_data=self._drop_conn_when_receiving_data,
                sleep_when_receiving_data=self._sleep_when_receiving_data,
                sock=sock,
                keep_alive=self.keep_alive,
                pipelined=self._pipelined,
            )
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

    def run_start(self):
        dbg(self, 3, "Start on %s:%d" % (self.ip, self.port), prefix="\t")
        self._reinit_variables()
        self.port_checker.check_ports_status()
        self._polling_lock.acquire()

        try:
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            self.set_reuse_addr()
            self.bind((self.ip, self.port))
            self.listen(socket.SOMAXCONN)
        except Exception as e:
            tf_cfg.dbg(2, "Error while creating socket: %s" % str(e))
            self._polling_lock.release()
            raise e

        self._polling_lock.release()

    def __stop_server(self):
        dbg(self, 3, "Stop", prefix="\t")
        self._polling_lock.acquire()

        self.close()
        connections = [conn for conn in self._connections]
        for conn in connections:
            conn.handle_close()

        self._polling_lock.release()

    def set_events(self, polling_lock):
        self._polling_lock = polling_lock

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
    def port(self) -> int:
        return self._port

    @port.setter
    def port(self, port: int) -> None:
        if port <= 0:
            raise ValueError("The server port MUST be greater than 0.")
        self._port = port

    @property
    def ip(self) -> str:
        return self._ip

    @ip.setter
    def ip(self, ip: str) -> None:
        ipaddress.ip_address(ip)
        self._ip = ip

    @property
    def conns_n(self) -> int:
        return self._conns_n

    @conns_n.setter
    def conns_n(self, conns_n: int) -> None:
        if conns_n < 0:
            raise ValueError("`conns_n` MUST be greater than or equal to 0.")
        self._conns_n = conns_n

    @property
    def keep_alive(self) -> int:
        return self._keep_alive

    @keep_alive.setter
    def keep_alive(self, keep_alive: int) -> None:
        if keep_alive < 0:
            raise ValueError("`keep_alive` MUST be greater than or equal to 0.")
        self._keep_alive = keep_alive

    @property
    def segment_size(self) -> int:
        return self._segment_size

    @segment_size.setter
    def segment_size(self, segment_size: int) -> None:
        if segment_size < 0:
            raise ValueError("`segment_size` MUST be greater than or equal to 0.")
        self._segment_size = segment_size

    @property
    def segment_gap(self) -> int:
        return self._segment_gap

    @segment_gap.setter
    def segment_gap(self, segment_gap: int) -> None:
        if segment_gap < 0:
            raise ValueError("`segment_gap` MUST be greater than or equal to 0.")
        self._segment_gap = segment_gap

    @property
    def last_request(self) -> deproxy.Request:
        return copy.deepcopy(self._last_request)

    @property
    def requests(self) -> list[deproxy.Request]:
        return list(self._requests)

    @property
    def connections(self) -> list[ServerConnection]:
        return list(self._connections)

    def remove_connection(self, connection: ServerConnection) -> None:
        self._connections.remove(connection)

    @property
    def drop_conn_when_receiving_data(self) -> bool:
        return self._drop_conn_when_receiving_data

    @drop_conn_when_receiving_data.setter
    def drop_conn_when_receiving_data(self, drop_conn: bool) -> None:
        self._drop_conn_when_receiving_data = drop_conn
        for connection in self.connections:
            connection._drop_conn_when_receiving_data = drop_conn

    @property
    def sleep_when_receiving_data(self) -> float:
        return self._sleep_when_receiving_data

    @sleep_when_receiving_data.setter
    def sleep_when_receiving_data(self, sleep: float) -> None:
        self._sleep_when_receiving_data = sleep
        for connection in self.connections:
            connection._sleep_when_receiving_data = sleep

    @property
    def pipelined(self) -> int:
        return self._pipelined

    @pipelined.setter
    def pipelined(self, pipelined: int) -> None:
        self._pipelined = pipelined

    @property
    def port_checker(self) -> port_checks.FreePortsChecker:
        return self._port_checker

    def receive_request(self, request: deproxy.Request) -> (bytes, bool):
        self._requests.append(request)
        self._last_request = request

        if self._deproxy_auto_parser.parsing:
            self._deproxy_auto_parser.check_expected_request(self.last_request)
            # Server sets expected response after receiving a request
            self._deproxy_auto_parser.prepare_expected_response(self.__response)

        return self.__response, False

    def wait_for_requests(self, n: int, timeout=5, strict=False) -> bool:
        """wait for the `n` number of responses to be received"""
        timeout_not_exceeded = util.wait_until(
            lambda: len(self.requests) < n,
            timeout=timeout,
            abort_cond=lambda: self.state != stateful.STATE_STARTED,
        )
        if strict:
            assert (
                timeout_not_exceeded != False
            ), f"Timeout exceeded while waiting connection close: {timeout}"
        return timeout_not_exceeded


def deproxy_srv_factory(server, name, tester):
    port = server["port"]
    rtype = server["response"]
    if rtype == "static":
        content = (
            fill_template(server["response_content"], server)
            if "response_content" in server
            else None
        )
        srv = StaticDeproxyServer(
            port=tempesta.upstream_port_start_from() if port == "default" else int(port),
            response=content,
            keep_original_data=server.get("keep_original_data", None),
            segment_size=server.get("segment_size", 0),
            segment_gap=server.get("segment_gap", 0),
            deproxy_auto_parser=tester._deproxy_auto_parser,
        )
    else:
        raise Exception("Invalid response type: %s" % str(rtype))

    tester.deproxy_manager.add_server(srv)
    return srv
