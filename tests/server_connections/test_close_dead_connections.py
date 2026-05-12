__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework.deproxy import deproxy_message
from framework.test_suite import marks, tester

BODY_SIZE = 1024**2 * 10  # MB
CONNS_N = 64


class FinishByClientBase(tester.TempestaTest):
    tempesta = {
        "config": f"""
    listen 80 proto=http;
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

    def configure_deproxy_server(self, conns_n, content_length, body_size) -> None:
        server = self.get_server("deproxy")
        server.conns_n = conns_n
        server.segment_size = 1024
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-type: text/html\r\n"
            + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
            + "Server: Deproxy Server\r\n"
            + f"Content-Length: {content_length}\r\n"
            + f"Date: {deproxy_message.HttpMessage.date_time_string()}\r\n"
            + "\r\n"
            + self.create_simpple_body(body_size)
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
    async def test_drop_server_connection_for_rst_stream(self):
        """
        Tempesta FW must close server connections
        when a client closes http2 streams using RST_STREAM
        and the server did not have time to send the full response.
        """
        server = self.get_server("deproxy")
        client = self.get_client("h2")

        self.configure_deproxy_server(CONNS_N, BODY_SIZE, BODY_SIZE - 10)
        self.disable_deproxy_auto_parser()
        await self.start_all_services(client=False)
        client.start()

        server_conn_list_before = set(server.connections)
        request = client.create_request(method="GET", headers=[])
        for _ in range(CONNS_N):
            client.make_request(request)

        await server.wait_for_requests(n=CONNS_N, timeout=10)

        for i in range(CONNS_N):
            client.send_reset_stream(stream_id=i * 2 + 1)

        await self.assertWaitUntilTrue(
            lambda: set(server_conn_list_before).isdisjoint(set(server.connections)),
            f"Tempesta FW must close dead connections.",
        )
        await server.wait_for_connections(
            timeout=5, msg=f"Tempesta FW must recreate dead connections."
        )


@marks.parameterize_class(
    [
        {"name": "Http", "deproxy_type": "deproxy", "port": "80", "ssl": False},
        {"name": "Https", "deproxy_type": "deproxy", "port": "443", "ssl": True},
        {"name": "H2", "deproxy_type": "deproxy_h2", "port": "443", "ssl": True},
    ]
)
class TestFinishTCPConnectionByClient(FinishByClientBase):

    deproxy_type: str = ""
    port: str = ""
    ssl: bool = False

    clients = [
        {
            "id": i,
            "addr": "${tempesta_ip}",
        }
        for i in range(CONNS_N)
    ]

    @classmethod
    def setUpClass(cls):
        for client in cls.clients:
            client["type"] = cls.deproxy_type
            client["port"] = cls.port
            client["ssl"] = cls.ssl
        super().setUpClass()

    async def __setup_test(self, rcv_buf_size, conns_n, content_length, body_size):
        server = self.get_server("deproxy")
        server.rcv_buf_size = rcv_buf_size
        self.configure_deproxy_server(conns_n, content_length, body_size)
        self.disable_deproxy_auto_parser()
        await self.start_all_services()

        return server

    @marks.Parameterize.expand(
        [
            marks.Param(name="client_rst", close_with_rst=True),
            marks.Param(name="client_fin", close_with_rst=False),
        ]
    )
    @marks.check_memory_consumption
    async def test_drop_server_connection_for(self, name, close_with_rst):
        """
        Tempesta FW must close server connections
        when a client closes a connection using RST/FIN TCP
        and the server did not have time to send the full response.
        """
        server = await self.__setup_test(
            rcv_buf_size=-1, conns_n=CONNS_N, content_length=BODY_SIZE, body_size=BODY_SIZE - 10
        )

        server_conn_list_before = set(server.connections)

        request = self.get_client(0).create_request(method="GET", headers=[])
        for client in self.get_clients():
            client.start()

        if close_with_rst:
            for client in self.get_clients():
                client.set_rst_tcp_to_closing_connection()
        for client in self.get_clients():
            client.make_request(request)
        await server.wait_for_requests(n=CONNS_N)
        for client in self.get_clients():
            client.stop()

        await self.assertWaitUntilTrue(
            lambda: set(server_conn_list_before).isdisjoint(set(server.connections)),
            f"Tempesta FW must close dead connections.",
        )
        await server.wait_for_connections(
            timeout=5, msg=f"Tempesta FW must recreate dead connections."
        )

    async def test_drop_request_of_closed_connection(self):
        """
        Tempesta FW must not send requests to the server if client
        closes a connection.
        """
        self.get_tempesta().config.defconfig = self.get_tempesta().config.defconfig.replace(
            "conns_n=64", "conns_n=1"
        )
        self.get_tempesta().config.defconfig = (
            self.get_tempesta().config.defconfig + "http_max_header_list_size 200000;\n"
        )
        server = await self.__setup_test(
            rcv_buf_size=2048, conns_n=1, content_length=10, body_size=10
        )
        self.assertEqual(len(server.connections), 1)
        server.connections[0].readable = lambda: False

        header_len = 150000
        request_long = self.get_client(0).create_request(
            method="GET", headers=[("a", "a" * header_len)]
        )
        request_short = self.get_client(0).create_request(method="GET", headers=[])

        for client in self.get_clients():
            client.start()

        i = 0
        for client in self.get_clients():
            if i == 0:
                client.make_requests([request_long] * 2)
            else:
                client.make_requests([request_short] * 2)
            i = i + 1
            await client.wait_for_client_sends_requests(timeout=10, strict=True)

        self.get_client(0).stop()
        server.connections[0].readable = lambda: True

        self.assertTrue(
            await server.wait_for_requests(n=(len(self.get_clients()) - 1) * 2, timeout=10),
            f"Tempesta FW must forward all requests from not dead client connections.",
        )

        self.assertFalse(
            await server.wait_for_requests(n=len(self.get_clients()) * 2, timeout=5),
            f"Tempesta FW must drop requests from already closed client connections.",
        )
        self.assertEqual(len(server.requests), (len(self.get_clients()) - 1) * 2 + 1)

        for i in range(1, len(self.get_clients())):
            self.assertEqual(len(client.responses), 2)
            for j in range(0, len(client.responses)):
                self.assertTrue(client.responses[j].status, "200")
