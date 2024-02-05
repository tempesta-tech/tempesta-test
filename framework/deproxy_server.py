import asyncore
import copy
import ipaddress
import socket
import sys
import threading
import time

import framework.port_checks as port_checks
import run_config
from helpers import deproxy, error, remote, stateful, tempesta, tf_cfg, util

dbg = deproxy.dbg

from .templates import fill_template

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
    ):
        super().__init__(sock=sock)
        self.__server = server
        self.__keep_alive = keep_alive
        self.__last_segment_time: int = 0
        self.__responses_done: int = 0
        self.__request_buffer: str = ""
        self.__response_buffer: list[bytes] = []
        self.drop_conn_when_receiving_data = drop_conn_when_receiving_data
        self.sleep_when_receiving_data = sleep_when_receiving_data
        dbg(self, 6, "New server connection", prefix="\t")

    def writable(self):
        if (
            self.__server.segment_gap != 0
            and time.time() - self.__last_segment_time < self.__server.segment_gap / 1000.0
        ):
            return False
        return (not self.connected) or len(self.__response_buffer) > self.__responses_done

    def handle_error(self):
        _, v, _ = sys.exc_info()
        error.bug("\tDeproxy: SrvConnection: %s" % v)

    def handle_close(self):
        dbg(self, 6, "Close connection", prefix="\t")
        self.close()

    def handle_read(self):
        self.__request_buffer += self.recv(deproxy.MAX_MESSAGE_SIZE).decode()

        dbg(self, 4, "Receive data:", prefix="\t")
        tf_cfg.dbg(5, self.__request_buffer)

        if self.__request_buffer and self.sleep_when_receiving_data:
            time.sleep(self.sleep_when_receiving_data)

        if self.drop_conn_when_receiving_data:
            self.close()

        while self.__request_buffer:
            try:
                request = deproxy.Request(
                    self.__request_buffer, keep_original_data=self.__server.keep_original_data
                )
            except deproxy.IncompleteMessage:
                return None
            except deproxy.ParseError as e:
                dbg(
                    self,
                    4,
                    ("Can't parse message\n" "<<<<<\n%s>>>>>" % self.__request_buffer),
                )
                return None

            dbg(self, 4, "Receive request:", prefix="\t")
            tf_cfg.dbg(5, request)
            response, need_close = self.__server.receive_request(request)
            if response:
                dbg(self, 4, "Send response:", prefix="\t")
                tf_cfg.dbg(5, response)
                self.__response_buffer.append(response)

            if need_close:
                self.close()
            self.__request_buffer = self.__request_buffer[request.original_length :]
        # Handler will be called even if buffer is empty.
        else:
            return None

    def handle_write(self):
        if run_config.TCP_SEGMENTATION and self.__server.segment_size == 0:
            self.__server.segment_size = run_config.TCP_SEGMENTATION

        segment_size = (
            self.__server.segment_size if self.__server.segment_size else deproxy.MAX_MESSAGE_SIZE
        )

        resp = self.__response_buffer[self.__responses_done]
        sent = self.socket.send(resp[:segment_size])

        if sent < 0:
            return
        self.__response_buffer[self.__responses_done] = resp[sent:]

        self.__last_segment_time = time.time()
        if self.__response_buffer[self.__responses_done] == b"":
            self.__responses_done += 1

        if self.__responses_done == self.__keep_alive and self.__keep_alive:
            self.handle_close()


class StaticDeproxyServer(asyncore.dispatcher, stateful.Stateful):
    def __init__(
        self,
        port: int,
        response: str | bytes | deproxy.Response = "",
        ip: str = tf_cfg.cfg.get("Server", "ip"),
        conns_n: int = tempesta.server_conns_default(),
        keep_alive: int = 0,
        segment_size: int = 0,
        segment_gap: int = 0,
        keep_original_data: bool = False,
    ):
        # Initialize the base `dispatcher`
        asyncore.dispatcher.__init__(self)

        self.port = port
        self.ip = ip
        self.response = response
        self.conns_n = conns_n
        self.keep_alive = keep_alive
        self.keep_original_data = keep_original_data

        # Following 2 parameters control heavy chunked testing
        # You can set it programmaticaly or via client config
        # TCP segment size, bytes, 0 for disable, usualy value of 1 is sufficient
        self.segment_size = segment_size
        # Inter-segment gap, ms, 0 for disable.
        # You usualy do not need it; update timeouts if you use it.
        self.segment_gap = segment_gap

        self.stop_procedures: list[callable] = [self.__stop_server]
        self.node: remote.Node = remote.host
        self.__polling_lock: threading.Lock | None = None
        self.__drop_conn_when_receiving_data = False
        self.__sleep_when_receiving_data = 0
        self.port_checker = port_checks.FreePortsChecker()

        self._reinit_variables()

    def _reinit_variables(self):
        self.__connections: list[ServerConnection] = list()
        self.__last_request: deproxy.Request | None = None
        self.__requests: list[deproxy.Request] = list()

    def drop_conn_when_receiving_data(self, drop_conn: bool) -> None:
        self.__drop_conn_when_receiving_data = drop_conn
        for connection in self.connections:
            connection.drop_conn_when_receiving_data = drop_conn

    def sleep_when_receiving_data(self, sleep: float) -> None:
        self.__sleep_when_receiving_data = sleep
        for connection in self.connections:
            connection.sleep_when_receiving_data = sleep

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, _ = pair
            if self.segment_size:
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            handler = ServerConnection(
                server=self,
                drop_conn_when_receiving_data=self.__drop_conn_when_receiving_data,
                sleep_when_receiving_data=self.__sleep_when_receiving_data,
                sock=sock,
                keep_alive=self.keep_alive,
            )
            self.__connections.append(handler)
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
        self.__polling_lock.acquire()

        try:
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            self.set_reuse_addr()
            self.bind((self.ip, self.port))
            self.listen(socket.SOMAXCONN)
        except Exception as e:
            tf_cfg.dbg(2, "Error while creating socket: %s" % str(e))
            self.__polling_lock.release()
            raise e

        self.__polling_lock.release()

    def __stop_server(self):
        dbg(self, 3, "Stop", prefix="\t")
        self.__polling_lock.acquire()

        self.close()
        connections = [conn for conn in self.__connections]
        for conn in connections:
            conn.handle_close()
            self.__connections.remove(conn)

        self.__polling_lock.release()

    def set_events(self, polling_lock):
        self.__polling_lock = polling_lock

    def wait_for_connections(self, timeout=1):
        if self.state != stateful.STATE_STARTED:
            return False

        return util.wait_until(
            lambda: len(self.__connections) < self.conns_n, timeout, poll_freq=0.001
        )

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
        return self.__port

    @port.setter
    def port(self, port: int) -> None:
        if port <= 0:
            raise ValueError("The server port MUST be greater than 0.")
        self.__port = port

    @property
    def ip(self) -> str:
        return self.__ip

    @ip.setter
    def ip(self, ip: str) -> None:
        ipaddress.ip_address(ip)
        self.__ip = ip

    @property
    def conns_n(self) -> int:
        return self.__conns_n

    @conns_n.setter
    def conns_n(self, conns_n: int) -> None:
        if conns_n <= 0:
            raise ValueError("`conns_n` MUST be greater than 0.")
        self.__conns_n = conns_n

    @property
    def keep_alive(self) -> int:
        return self.__keep_alive

    @keep_alive.setter
    def keep_alive(self, keep_alive: int) -> None:
        if keep_alive < 0:
            raise ValueError("`keep_alive` MUST be greater than or equal to 0.")
        self.__keep_alive = keep_alive

    @property
    def segment_size(self) -> int:
        return self.__segment_size

    @segment_size.setter
    def segment_size(self, segment_size: int) -> None:
        if segment_size < 0:
            raise ValueError("`segment_size` MUST be greater than or equal to 0.")
        self.__segment_size = segment_size

    @property
    def segment_gap(self) -> int:
        return self.__segment_gap

    @segment_gap.setter
    def segment_gap(self, segment_gap: int) -> None:
        if segment_gap < 0:
            raise ValueError("`segment_gap` MUST be greater than or equal to 0.")
        self.__segment_gap = segment_gap

    @property
    def last_request(self) -> deproxy.Request:
        return copy.deepcopy(self.__last_request)

    @property
    def requests(self) -> list[deproxy.Request]:
        return list(self.__requests)

    @property
    def connections(self) -> list[ServerConnection]:
        return list(self.__connections)

    def receive_request(self, request: deproxy.Request) -> (bytes, bool):
        self.__requests.append(request)
        self.__last_request = request
        return self.__response, False


def deproxy_srv_factory(server, name, tester):
    port = server["port"]
    if port == "default":
        port = tempesta.upstream_port_start_from()
    else:
        port = int(port)
    srv = None
    ko = server.get("keep_original_data", None)
    ss = server.get("segment_size", 0)
    sg = server.get("segment_gap", 0)
    rtype = server["response"]
    if rtype == "static":
        content = (
            fill_template(server["response_content"], server)
            if "response_content" in server
            else None
        )
        srv = StaticDeproxyServer(
            port=port, response=content, keep_original_data=ko, segment_size=ss, segment_gap=sg
        )
    else:
        raise Exception("Invalid response type: %s" % str(rtype))

    tester.deproxy_manager.add_server(srv)
    return srv
