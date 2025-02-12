__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

from helpers.deproxy import HttpMessage
from test_suite import marks, tester


@marks.parameterize_class(
    [{"name": "Https", "client_type": "deproxy"}, {"name": "H2", "client_type": "deproxy_h2"}]
)
class TestIPv6(tester.TempestaTest):
    client_type: str

    backends = [
        {
            "id": "deproxy-v4",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + "Server: debian\r\n"
                + f"Date: {HttpMessage.date_time_string()}\r\n"
                + "X-My-Hdr: ipv4\r\n"
                + "Content-Length: 0\r\n\r\n"
            ),
        },
        {
            "id": "deproxy-v6",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "is_ipv6": True,
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + "Server: debian\r\n"
                + f"Date: {HttpMessage.date_time_string()}\r\n"
                + "X-My-Hdr: ipv6\r\n"
                + "Content-Length: 0\r\n\r\n"
            ),
        },
    ]

    clients = [
        {
            "id": "deproxy-v4",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "deproxy-v6",
            "addr": "${tempesta_ipv6}",
            "port": "443",
            "ssl": True,
            "is_ipv6": True,
        },
    ]

    tempesta = {
        "config": """
            listen ${tempesta_ip}:443 proto=h2,https;
            listen [${tempesta_ipv6}]:443 proto=h2,https;

            srv_group ipv4 {server ${server_ip}:8000;}
            srv_group ipv6 {server [${server_ipv6}]:8000;}

            frang_limits {http_strict_host_checking false;}

            vhost ipv4 {proxy_pass ipv4;}
            vhost ipv6 {proxy_pass ipv6;}

            http_chain {
                uri == "/ipv4" -> ipv4;
                uri == "/ipv6" -> ipv6;
            }

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;

            block_action attack reply;
            block_action error reply;
        """
    }

    @classmethod
    def setUpClass(cls):
        for client in cls.clients:
            client["type"] = cls.client_type
        super().setUpClass()

    @marks.Parameterize.expand(
        [
            marks.Param(name="ipv6_to_ipv6", client="deproxy-v6", server="deproxy-v6", uri="/ipv6"),
            marks.Param(name="ipv4_to_ipv6", client="deproxy-v4", server="deproxy-v6", uri="/ipv6"),
            marks.Param(name="ipv6_to_ipv4", client="deproxy-v6", server="deproxy-v4", uri="/ipv4"),
        ]
    )
    def test(self, name, client: str, server: str, uri: str):
        client = self.get_client(client)
        server = self.get_server(server)

        self.start_all_services()

        data_size = 5000
        response_header = ("x-my-hdr", "x" * data_size)
        response_body = "x" * data_size
        request_header = ("x-my-hdr", "z" * data_size)
        request_body = "z" * data_size

        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + "Server: debian\r\n"
            + f"{response_header[0]}: {response_header[1]}\r\n"
            + f"Content-Length: {len(response_body)}\r\n\r\n"
            + response_body
        )
        client.send_request(
            request=client.create_request(
                method="POST",
                uri=uri,
                headers=[("Content-Length", str(data_size)), request_header],
                body=request_body,
            ),
            expected_status_code="200",
        )

        self.assertEqual(request_body, server.last_request.body)
        self.assertEqual(response_body, client.last_response.body)
        self.assertIn(request_header, server.last_request.headers.headers)
        self.assertIn(response_header, client.last_response.headers.headers)
