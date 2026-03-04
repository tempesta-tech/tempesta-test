__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

from h2.errors import ErrorCodes

from framework.deproxy import deproxy_message
from framework.test_suite import marks, tester

BODY_SIZE = 1024**2 * 10  # MB
CONNS_N = 64


class FinishByClientBase(tester.TempestaTest):
    tempesta = {
        "config": f"""
    listen 443 proto=h2,https;

    server ${{server_ip}}:8000 conns_n={CONNS_N};
    frang_limits {{ http_methods get put post; }}

    frang_limits {{http_strict_host_checking false;}}
    tls_certificate ${{tempesta_workdir}}/tempesta.crt;
    tls_certificate_key ${{tempesta_workdir}}/tempesta.key;
    tls_match_any_server_name;
    cache 0;
    """
    }

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
        }
    ]

    def configure_deproxy_server(self) -> None:
        server = self.get_server("deproxy")
        server.conns_n = CONNS_N
        server.segment_size = 1024
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-type: text/html\r\n"
            + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
            + "Server: Deproxy Server\r\n"
            + f"Content-Length: {BODY_SIZE}\r\n"
            + f"Date: {deproxy_message.HttpMessage.date_time_string()}\r\n"
            + "\r\n"
            + self.create_simpple_body(BODY_SIZE - 10)
        )

    @staticmethod
    def create_simpple_body(body_size: int) -> str:
        return "x" * body_size


class TestFinishH2StreamsByClient(FinishByClientBase):

    clients = [
        {
            "id": "h2",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    @marks.check_memory_consumption
    def test_drop_server_connection_for_rst_stream(self):
        """
        Tempesta FW must close server connections
        when a client closes http2 streams using RST_STREAM
        and the server did not have time to send the full response.
        """
        server = self.get_server("deproxy")
        client = self.get_client("h2")

        self.configure_deproxy_server()
        self.disable_deproxy_auto_parser()
        self.start_all_services(client=False)
        client.start()

        server_conn_list_before = set(server.connections)
        request = client.create_request(method="GET", headers=[])
        for _ in range(CONNS_N):
            client.make_request(request)

        server.wait_for_requests(strict=True, n=CONNS_N)

        for i in range(CONNS_N):
            client.send_reset_stream(stream_id=i * 2 + 1)

        self.assertWaitUntilTrue(
            lambda: set(server_conn_list_before).isdisjoint(set(server.connections)),
            f"Tempesta FW must close dead connections.",
        )
        self.assertTrue(
            server.wait_for_connections(timeout=5), f"Tempesta FW must recreate dead connections."
        )

    @marks.check_memory_consumption
    def test_drop_server_connection_for_goaway(self):
        """
        Tempesta FW must close server connections
        when a client closes http2 connection using GOAWAY with any Last-Stream-ID
        and the server did not have time to send the full response.
        """
        server = self.get_server("deproxy")
        client = self.get_client("h2")

        self.configure_deproxy_server()
        self.disable_deproxy_auto_parser()
        self.start_all_services(client=False)
        client.start()

        server_conn_list_before = set(server.connections)
        request = client.create_request(method="POST", headers=[])
        for _ in range(CONNS_N):
            client.make_request(request)

        server.wait_for_requests(strict=True, n=CONNS_N)

        client.send_goaway(error_code=ErrorCodes.PROTOCOL_ERROR, last_stream_id=CONNS_N * 2 + 1)

        self.assertWaitUntilTrue(
            lambda: set(server_conn_list_before).isdisjoint(set(server.connections)),
            f"Tempesta FW must close dead connections.",
        )
        self.assertTrue(
            server.wait_for_connections(timeout=5), f"Tempesta FW must recreate dead connections."
        )


@marks.parameterize_class(
    [{"name": "Https", "deproxy_type": "deproxy"}, {"name": "H2", "deproxy_type": "deproxy_h2"}]
)
class TestFinishTCPConnectionByClient(FinishByClientBase):

    deproxy_type: str = ""

    clients = [
        {
            "id": i,
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        }
        for i in range(CONNS_N)
    ]

    @classmethod
    def setUpClass(cls):
        for client in cls.clients:
            client["type"] = cls.deproxy_type
        super().setUpClass()

    @marks.Parameterize.expand(
        [
            marks.Param(name="client_rst", close_with_rst=True),
            marks.Param(name="client_fin", close_with_rst=False),
        ]
    )
    @marks.check_memory_consumption
    def test_drop_server_connection_for(self, name, close_with_rst):
        """
        Tempesta FW must close server connections
        when a client closes a connection using RST/FIN TCP
        and the server did not have time to send the full response.
        """
        server = self.get_server("deproxy")
        self.configure_deproxy_server()
        self.disable_deproxy_auto_parser()
        self.start_all_services()

        server_conn_list_before = set(server.connections)

        request = self.get_client(0).create_request(method="GET", headers=[])
        for client in self.get_clients():
            client.start()

        if close_with_rst:
            for client in self.get_clients():
                client.set_rst_tcp_to_closing_connection()
        for client in self.get_clients():
            client.make_request(request)
        server.wait_for_requests(strict=True, n=CONNS_N)
        for client in self.get_clients():
            client.stop()

        self.assertWaitUntilTrue(
            lambda: set(server_conn_list_before).isdisjoint(set(server.connections)),
            f"Tempesta FW must close dead connections.",
        )
        self.assertTrue(
            server.wait_for_connections(timeout=5), f"Tempesta FW must recreate dead connections."
        )
