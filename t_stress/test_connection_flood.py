"""
HTTP Stress tests - load Tempesta FW with multiple connections.
"""

import socket
import struct
import time

from h2.connection import H2Connection
from h2.settings import SettingCodes, Settings

from framework.deproxy_client import DeproxyClient, DeproxyClientH2, HuffmanEncoder
from framework.deproxy_server import ServerConnection, StaticDeproxyServer
from helpers import deproxy, tf_cfg
from helpers.deproxy import HttpMessage
from test_suite import marks, tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2026 Tempesta Technologies, Inc."
__license__ = "GPL2"


class BaseClientWaitForFinish:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.connection_closed = False
        self.initialized_at = time.time()

    def is_time_out(self, timeout: int):
        return (time.time() - self.initialized_at) > timeout

    def wait_for_finish(self, timeout):

        while not self.connection_closed and not self.is_time_out(timeout):
            time.sleep(0.001)

        return True


class FloodClientH1SmallRequest(BaseClientWaitForFinish, DeproxyClient):
    def flood(self, client_id: str):
        self.make_request(self.create_request(method="POST", headers=[("client-id", client_id)]))

    def is_stream_ready(self):
        return True


class FloodClientH2SmallRequest(BaseClientWaitForFinish, DeproxyClientH2):
    """
    Initiate the connection closing from client side after
    the half of small response sent
    """

    def update_initial_settings(self, *_, **__) -> None:
        self.h2_connection = H2Connection()
        self.h2_connection.encoder = HuffmanEncoder()
        self.encoder = HuffmanEncoder()

        self.h2_connection.local_settings = Settings(
            initial_values={
                SettingCodes.ENABLE_PUSH: 0,
                SettingCodes.INITIAL_WINDOW_SIZE: 0,
                SettingCodes.MAX_FRAME_SIZE: 1 << 24 - 1,
                SettingCodes.MAX_HEADER_LIST_SIZE: 10 << 20,
                SettingCodes.HEADER_TABLE_SIZE: 4096,
            }
        )

    def flood(self, client_id: int):
        self.h2_connection.initiate_connection()
        self.send_bytes(self.h2_connection.data_to_send())

        self.h2_connection.send_headers(
            stream_id=1,
            end_stream=True,
            headers=[
                (":authority", "example.com"),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "POST"),
                ("client-id", str(client_id)),
            ],
        )

        data_to_send = self.h2_connection.data_to_send()
        self.send_bytes(data_to_send)

    def is_stream_ready(self):
        return self.h2_connection.streams.get(1)


class FloodClientH1LargeRequest(FloodClientH1SmallRequest):
    def flood(self, client_id: int):
        self.make_request(
            self.create_request(
                method="POST",
                headers=[("client-id", str(client_id))],
                body="H" * 16384,
            )
        )


class FloodClientH2LargeRequest(FloodClientH2SmallRequest):

    def flood(self, client_id: int):
        self.h2_connection.initiate_connection()
        self.send_bytes(self.h2_connection.data_to_send())

        request_body = b"H" * 16384

        self.h2_connection.send_headers(
            stream_id=1,
            end_stream=False,
            headers=[
                (":authority", "example.com"),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "POST"),
                ("client-id", str(client_id)),
                ("content-type", "plain/text"),
                ("content-length", str(len(request_body))),
            ],
        )

        data_to_send = self.h2_connection.data_to_send()
        self.send_bytes(data_to_send)

        self.h2_connection.send_data(
            stream_id=1,
            data=request_body,
            end_stream=True,
        )
        data_to_send = self.h2_connection.data_to_send()
        self.send_bytes(data_to_send)


class LifespanServerConnection(ServerConnection):
    """
    Initiate the connection closing from client side after
    the half of huge response sent
    """

    def __init__(
        self,
        *args,
        flood_clients: dict[str, FloodClientH2SmallRequest | FloodClientH2LargeRequest] = None,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.flood_clients = flood_clients

    def close_client_connection(self, client_id: str):
        if self._server.rst_close:
            self.flood_clients[client_id].socket.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_LINGER,
                struct.pack("ii", 1, 0),
            )

        self.flood_clients[client_id].socket.shutdown(socket.SHUT_WR)
        self.flood_clients[client_id].socket.close()
        self.flood_clients[client_id].connection_closed = True

    def send_data(self, request: deproxy.Request, data: bytes) -> int:
        client_id = request.headers["client-id"]
        half_of_response = len(data) // 2

        sent = self.socket.send(data[:half_of_response])
        self.close_client_connection(client_id)
        sent += self.socket.send(data[half_of_response:])
        return sent


class DeproxyServerWithCallback(StaticDeproxyServer):

    def __init__(
        self,
        *args,
        flood_clients: dict[str, FloodClientH2SmallRequest | FloodClientH2LargeRequest] = None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.flood_clients = flood_clients
        self.response_size = 0
        self.response_body = ""
        self.rst_close = False

    def create_new_connection(self, sock):
        return LifespanServerConnection(server=self, sock=sock, flood_clients=self.flood_clients)

    def set_response_size(self, size: int) -> None:
        self.response_size = size
        self.response_body = "x" * size
        self.set_response(
            "HTTP/1.1 200 OK\r\n"
            "Server: Debian\r\n"
            f"Date: {HttpMessage.date_time_string()}\r\n"
            f"Content-Length: {self.response_size}\r\n\r\n"
            f"{self.response_body}"
        )

    def close_with_rst(self, rst_close: bool):
        self.rst_close = rst_close


class LifespanServerCloseAfterHeaders(LifespanServerConnection):
    """
    Initiate the connection closing from client side
    the response headers sent
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.headers_sent = False

    def send_data(self, request: deproxy.Request, data: bytes) -> int:
        client_id = request.headers["client-id"]

        if not self.headers_sent:
            headers = (
                "HTTP/1.1 200 OK\r\n"
                "Server: Debian\r\n"
                f"Date: {HttpMessage.date_time_string()}\r\n"
                f"Content-Length: {self._server.response_size}\r\n\r\n"
            )
            sent = self.socket.send(headers.encode())
            self.headers_sent = True
            return sent

        if not self.flood_clients[client_id].is_stream_ready():
            return 0

        self.close_client_connection(client_id)

        sent = self.socket.send(self._server.response_body.encode())
        return sent


class DeproxyServerHeaders(DeproxyServerWithCallback):
    def create_new_connection(self, sock):
        return LifespanServerCloseAfterHeaders(
            server=self, sock=sock, flood_clients=self.flood_clients
        )


class LifespanServerSegmented(LifespanServerConnection):
    """
    Initiate the connection closing from client side after
    half of response segments sent. Each segment sends with
    1-second delay.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.headers_sent = False
        self.segment_size = 2000
        self.total_segments_to_stop = None
        self.segments_sent = 0
        self.last_sent = time.time()
        self.delay_between_segments = 1

    def send_data(self, request: deproxy.Request, data: bytes) -> int:
        time_since_last_sent = time.time() - self.last_sent

        if time_since_last_sent < self.delay_between_segments:
            return 0

        if not self.total_segments_to_stop:
            self.total_segments_to_stop = len(data) // self.segment_size // 2

        client_id = request.headers["client-id"]

        sent = self.socket.send(data[: self.segment_size])

        if not sent:
            return 0

        self.segments_sent += 1
        self.last_sent = time.time()

        if self.segments_sent >= self.total_segments_to_stop:
            self.close_client_connection(client_id)

        return sent


class DeproxyServerSegmented(DeproxyServerWithCallback):
    def create_new_connection(self, sock):
        return LifespanServerSegmented(server=self, sock=sock, flood_clients=self.flood_clients)


@marks.parameterize_class(
    [
        {
            "name": "SmallReqSmallResp",
            "client": FloodClientH1SmallRequest,
            "server": DeproxyServerWithCallback,
            "response_size": 200,
        },
        {
            "name": "SmallReqLargeResp",
            "client": FloodClientH1SmallRequest,
            "server": DeproxyServerWithCallback,
            "response_size": 200_000,
        },
        {
            "name": "LargeReqSmallResp",
            "client": FloodClientH1LargeRequest,
            "server": DeproxyServerWithCallback,
            "response_size": 200,
        },
        {
            "name": "LargeReqLargeResp",
            "client": FloodClientH1LargeRequest,
            "server": DeproxyServerWithCallback,
            "response_size": 200_000,
        },
        {
            "name": "AfterHeaders",
            "client": FloodClientH1SmallRequest,
            "server": DeproxyServerHeaders,
            "response_size": 200_000,
        },
        {
            "name": "Segmented",
            "client": FloodClientH1SmallRequest,
            "server": DeproxyServerSegmented,
            "response_size": 200_000,
        },
    ]
)
class TestConnectionFloodH1(tester.TempestaTest):
    client = None
    server = None
    response_size = 0

    tempesta = {
        "config": """
        listen 443 proto=https;

        access_log dmesg;
        server ${server_ip}:8000;
        frang_limits {http_methods GET HEAD POST PUT DELETE;}
        
        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;
        
        cache 0;
    """
    }

    def setUp(self):
        super().setUp()

        for index in enumerate(range(1000)):
            client = self.client(
                id_=f"deproxy_flood_{index}",
                deproxy_auto_parser=self.get_deproxy_auto_parser(),
                port=443,
                bind_addr=tf_cfg.cfg.get("Server", "ip"),
                segment_gap=0,
                segment_size=0,
                is_ipv6=False,
                conn_addr=tf_cfg.cfg.get("Tempesta", "ip"),
                is_ssl=True,
                server_hostname="tempesta-tech.com",
            )
            self.add_client(client)
            self.deproxy_manager.add_client(client)

        server = self.server(
            id_="deproxy",
            deproxy_auto_parser=self.get_deproxy_auto_parser(),
            flood_clients={client.get_name(): client for client in self.get_clients()},
            port=8000,
            bind_addr=tf_cfg.cfg.get("Server", "ip"),
            segment_size=0,
            segment_gap=0,
            is_ipv6=False,
            response=b"",
            keep_alive=True,
            drop_conn_when_request_received=False,
            delay_before_sending_response=0.0,
            hang_on_req_num=0,
            pipelined=0,
        )
        self.add_server(server)
        self.deproxy_manager.add_server(server)

    def run_test(self, rst_close: bool):
        self.start_all_services(client=False)

        server: DeproxyServerWithCallback = self.get_server("deproxy")
        server.set_response_size(self.response_size)
        server.close_with_rst(rst_close)

        self.assertTrue(self.wait_all_connections())

        for client in self.get_clients():
            client.start()
            client.flood(client_id=client.get_name())

        self.wait_while_busy(*self.get_clients())

        self.loggers.dmesg.update()

        logs = self.loggers.dmesg.log_findall(
            "request dropped: non-idempotent requests "
            "aren't re-forwarded or re-scheduled, status 504"
        )
        self.assertEqual(len(logs), 0, "Dropped requests")

        logs = self.loggers.dmesg.log_findall("Close TCP socket w/o sending alert to the peer")
        self.assertEqual(len(logs), 0, "Problems with closing TCP connections")

        logs = self.loggers.dmesg.log_findall("Cannot send TLS alert")
        self.assertEqual(len(logs), 0, "TLS alerts exists")

        logs = self.loggers.dmesg.log_findall(" 504 ")
        self.assertEqual(len(logs), 0, "Timeout requests exists")

        logs = self.loggers.dmesg.log_findall(" 200 ")
        self.assertGreater(len(logs), 0, "No successful responses")

    @marks.Parameterize.expand(
        [
            marks.Param(name="FIN", rst_close=False),
            marks.Param(name="RST", rst_close=True),
        ]
    )
    def test_connection_flood(self, *_, rst_close: bool = False, **__):
        self.run_test(rst_close=rst_close)


@marks.parameterize_class(
    [
        {
            "name": "SmallReqSmallResp",
            "client": FloodClientH2SmallRequest,
            "server": DeproxyServerWithCallback,
            "response_size": 200,
        },
        {
            "name": "SmallReqLargeResp",
            "client": FloodClientH2SmallRequest,
            "server": DeproxyServerWithCallback,
            "response_size": 200_000,
        },
        {
            "name": "LargeReqSmallResp",
            "client": FloodClientH2LargeRequest,
            "server": DeproxyServerWithCallback,
            "response_size": 200,
        },
        {
            "name": "LargeReqLargeResp",
            "client": FloodClientH2LargeRequest,
            "server": DeproxyServerWithCallback,
            "response_size": 200_000,
        },
        {
            "name": "AfterHeaders",
            "client": FloodClientH2SmallRequest,
            "server": DeproxyServerHeaders,
            "response_size": 200_000,
        },
        {
            "name": "H2Segmented",
            "client": FloodClientH2SmallRequest,
            "server": DeproxyServerSegmented,
            "response_size": 200_000,
        },
    ]
)
class TestConnectionFloodH2(TestConnectionFloodH1):
    tempesta = {
        "config": """
        listen 443 proto=h2,https;

        access_log dmesg;
        server ${server_ip}:8000;
        frang_limits {http_methods GET HEAD POST PUT DELETE;}
        
        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;
        
        cache 0;
    """
    }

    @marks.Parameterize.expand(
        [
            marks.Param(name="FIN", rst_close=False),
            marks.Param(name="RST", rst_close=True),
        ]
    )
    def test_connection_flood(self, *_, rst_close: bool = False, **__):
        self.run_test(rst_close=rst_close)
