__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework.deproxy import deproxy_message
from framework.helpers import util
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
    
    http_max_header_list_size 200000;
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

    def configure_deproxy_server(
        self, *, conns_n: int, content_length: int, body_size: int
    ) -> None:
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

        self.configure_deproxy_server(
            conns_n=CONNS_N, content_length=BODY_SIZE, body_size=BODY_SIZE - 10
        )
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
        server = self.get_server("deproxy")
        self.configure_deproxy_server(
            conns_n=CONNS_N, content_length=BODY_SIZE, body_size=BODY_SIZE - 10
        )
        self.disable_deproxy_auto_parser()
        await self.start_all_services()

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

        We consider such requests as dead and remove them from the server connection queue.
        Such requests are not removed from the queue when the connection is closed by the client.

        This behavior is necessary to avoid memory loss on dead connections.
        """
        tempesta = self.get_tempesta()
        server = self.get_server("deproxy")
        bad_client = self.get_client(0)
        valid_clients = util.ForEach(*self.get_clients()[1:])  # first client is bad
        client_req_n = 5

        tempesta.config.replace("conns_n=64", "conns_n=1")
        server.rcv_buf_size = 2048
        self.configure_deproxy_server(conns_n=1, content_length=10, body_size=10)
        self.disable_deproxy_auto_parser()
        await self.start_all_services()

        self.assertEqual(len(server.connections), 1)
        server.connections[0].readable = lambda: False

        request_long = bad_client.create_request(
            method="GET", uri="/long", headers=[("a", "a" * 150000)]
        )
        request_short = bad_client.create_request(method="GET", uri="/short", headers=[])

        bad_client.make_request(request_long)
        await self.assertWaitUntilEqual(lambda: tempesta.stats.get("cl_msg_forwarded"), 1)

        bad_client.make_requests([request_long] * client_req_n)
        valid_clients.make_requests([request_short] * client_req_n)
        await self.assertWaitUntilEqual(
            lambda: tempesta.stats.get("cl_msg_forwarded"),
            client_req_n * len(self.get_clients()) + 1,
            "Tempesta FW doesn't forward all requests to the server.",
        )

        bad_client.stop()
        server.connections[0].readable = lambda: True

        await server.wait_for_requests(n=len(list(valid_clients)) * client_req_n, timeout=10)

        self.assertEqual(
            len(server.requests),
            (len(list(valid_clients)) * client_req_n + 1),
            "Tempesta FW must forward requests to the server: client_N * client_requests_N + 1 (bad_requests).",
        )

        await valid_clients.wait_for_response(msg="The valid clients doesn't receive responses.")

        for client in valid_clients:
            self.assertEqual(len(client.responses), client_req_n)
            for response in client.responses:
                self.assertTrue(response.status, "200")

        self.assertEqual(
            1,
            len([req for req in server.requests if "/long" in req.uri]),
            "Tempesta FW sent requests to the server from the client that already closed the connection.",
        )
