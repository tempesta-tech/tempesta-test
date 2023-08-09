import abc
import asyncore
import io
import socket
import sys
import threading
import time

import framework.port_checks as port_checks
import framework.tester
import run_config
from helpers import deproxy, error, remote, stateful, tempesta, tf_cfg, util

from .templates import fill_template

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"


class ServerConnection(asyncore.dispatcher_with_send):
    def __init__(self, server, sock=None, keep_alive=None):
        asyncore.dispatcher_with_send.__init__(self, sock)
        self.out_buffer = b""
        self.server = server
        self.keep_alive = keep_alive
        self.last_segment_time = 0
        self.responses_done = 0
        self.request_buffer = ""
        tf_cfg.dbg(6, "\tDeproxy: SrvConnection: New server connection.")

    def initiate_send(self):
        """Override dispatcher_with_send.initiate_send() which transfers
        data with too small chunks of 512 bytes.
        However if server.segment_size is set (!=0), use this value.
        """
        if run_config.TCP_SEGMENTATION and self.server.segment_size == 0:
            self.server.segment_size = run_config.TCP_SEGMENTATION

        segment_size = (
            self.server.segment_size if self.server.segment_size else deproxy.MAX_MESSAGE_SIZE
        )

        sent = self.socket.send(self.out_buffer[:segment_size])
        if sent < 0:
            return
        self.out_buffer = self.out_buffer[sent:]

        self.last_segment_time = time.time()
        self.responses_done += 1

        if self.responses_done == self.keep_alive and self.keep_alive:
            self.handle_close()

    def writable(self):
        if (
            self.server.segment_gap != 0
            and time.time() - self.last_segment_time < self.server.segment_gap / 1000.0
        ):
            return False
        return asyncore.dispatcher_with_send.writable(self)

    def handle_error(self):
        _, v, _ = sys.exc_info()
        error.bug("\tDeproxy: SrvConnection: %s" % v)

    def handle_close(self):
        tf_cfg.dbg(6, "\tDeproxy: SrvConnection: Close connection.")
        self.close()
        if self.server:
            try:
                self.server.connections.remove(self)
            except ValueError:
                pass

    def handle_read(self):
        self.request_buffer += self.recv(deproxy.MAX_MESSAGE_SIZE).decode()

        tf_cfg.dbg(4, "\tDeproxy: SrvConnection: Receive data.")
        tf_cfg.dbg(5, self.request_buffer)

        while self.request_buffer:
            try:
                request = deproxy.Request(
                    self.request_buffer, keep_original_data=self.server.keep_original_data
                )
            except deproxy.IncompleteMessage:
                return None
            except deproxy.ParseError as e:
                tf_cfg.dbg(
                    4,
                    (
                        "Deproxy: SrvConnection: Can't parse message\n"
                        "<<<<<\n%s>>>>>" % self.request_buffer
                    ),
                )

            tf_cfg.dbg(4, "\tDeproxy: SrvConnection: Receive request.")
            tf_cfg.dbg(5, request)
            response, need_close = self.server.receive_request(request)
            if response:
                tf_cfg.dbg(4, "\tDeproxy: SrvConnection: Send response.")
                tf_cfg.dbg(5, response)
                self.out_buffer += response
            if need_close:
                self.close()
            self.request_buffer = self.request_buffer[request.original_length :]
        # Handler will be called even if buffer is empty.
        else:
            return None


class BaseDeproxyServer(deproxy.Server, port_checks.FreePortsChecker):
    def __init__(self, *args, **kwargs):
        # This parameter controls whether to keep original data with the request
        # (See deproxy.HttpMessage.original_data)
        self.keep_original_data = kwargs.pop("keep_original_data", None)

        # Following 2 parameters control heavy chunked testing
        # You can set it programmaticaly or via client config
        # TCP segment size, bytes, 0 for disable, usualy value of 1 is sufficient
        self.segment_size = kwargs.pop("segment_size", 0)
        # Inter-segment gap, ms, 0 for disable.
        # You usualy do not need it; update timeouts if you use it.
        self.segment_gap = kwargs.pop("segment_gap", 0)

        deproxy.Server.__init__(self, *args, **kwargs)
        self.stop_procedures = [self.__stop_server]
        self.is_polling = threading.Event()
        self.sockets_changing = threading.Event()
        self.node = remote.host

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, _ = pair
            if self.segment_size:
                sock.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            handler = ServerConnection(server=self, sock=sock, keep_alive=self.keep_alive)
            self.connections.append(handler)
            # ATTENTION
            # Due to the polling cycle, creating new connection can be
            # performed before removing old connection.
            # So we can have case with > expected amount of connections
            # It's not a error case, it's a problem of polling

    def run_start(self):
        tf_cfg.dbg(3, "\tDeproxy: Server: Start on %s:%d." % (self.ip, self.port))
        self.check_ports_status()
        self.polling_lock.acquire()

        try:
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            self.set_reuse_addr()
            self.bind((self.ip, self.port))
            self.listen(socket.SOMAXCONN)
        except Exception as e:
            tf_cfg.dbg(2, "Error while creating socket: %s" % str(e))
            self.polling_lock.release()
            raise e

        self.polling_lock.release()

    def __stop_server(self):
        tf_cfg.dbg(3, "\tDeproxy: Server: Stop on %s:%d." % (self.ip, self.port))
        self.polling_lock.acquire()

        self.close()
        connections = [conn for conn in self.connections]
        for conn in connections:
            conn.handle_close()
        if self.tester:
            self.tester.servers.remove(self)

        self.polling_lock.release()

    def set_events(self, polling_lock):
        self.polling_lock = polling_lock

    def wait_for_connections(self, timeout=1):
        if self.state != stateful.STATE_STARTED:
            return False

        return util.wait_until(
            lambda: len(self.connections) < self.conns_n, timeout, poll_freq=0.001
        )

    @abc.abstractmethod
    def receive_request(self, request):
        raise NotImplementedError("Not implemented 'receive_request()'")


class StaticDeproxyServer(BaseDeproxyServer):
    __response: str or bytes

    def __init__(self, *args, **kwargs):
        self.set_response(kwargs["response"])
        kwargs.pop("response", None)
        BaseDeproxyServer.__init__(self, *args, **kwargs)
        self.last_request = None
        self.requests = []

    def run_start(self):
        self.requests = []
        BaseDeproxyServer.run_start(self)

    @property
    def response(self) -> str:
        return self.__response.decode(errors="ignore")

    @response.setter
    def response(self, response: str or bytes) -> None:
        self.set_response(response)

    def set_response(self, response: str or bytes) -> None:
        if isinstance(response, str):
            self.__response = response.encode()
        elif isinstance(response, bytes):
            self.__response = response

    def receive_request(self, request):
        self.requests.append(request)
        self.last_request = request
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
        content = fill_template(server["response_content"], server)
        srv = StaticDeproxyServer(
            port=port, response=content, keep_original_data=ko, segment_size=ss, segment_gap=sg
        )
    else:
        raise Exception("Invalid response type: %s" % str(rtype))

    tester.deproxy_manager.add_server(srv)
    return srv


framework.tester.register_backend("deproxy", deproxy_srv_factory)
