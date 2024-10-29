"""Functional tests for tcp options frames."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from helpers.deproxy import HttpMessage
from helpers.networker import NetWorker
from test_suite import marks, tester

DEPROXY_CLIENT = {
    "id": "deproxy",
    "type": "deproxy",
    "addr": "${tempesta_ip}",
    "port": "80",
}

DEPROXY_CLIENT_SSL = {
    "id": "deproxy",
    "type": "deproxy",
    "addr": "${tempesta_ip}",
    "port": "443",
    "ssl": True,
}

DEPROXY_CLIENT_H2 = {
    "id": "deproxy",
    "type": "deproxy_h2",
    "addr": "${tempesta_ip}",
    "port": "443",
    "ssl": True,
}


@marks.parameterize_class(
    [
        {"name": "Http", "clients": [DEPROXY_CLIENT]},
        {"name": "Https", "clients": [DEPROXY_CLIENT_SSL]},
        {"name": "H2", "clients": [DEPROXY_CLIENT_H2]},
    ]
)
class TestTcpOptions(tester.TempestaTest, NetWorker):
    tempesta = {
        "config": """
            listen 80;
            listen 443 proto=h2,https;
            server ${server_ip}:8000;
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;
            frang_limits {
                http_strict_host_checking false;
            }
        """
    }

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + f"Date: {HttpMessage.date_time_string()}\r\n"
                + "Server: debian\r\n"
                + "Content-Length: 0\r\n\r\n"
            ),
        }
    ]

    def __test(self, client, server):
        self.start_all_services()
        header = ("qwerty", "x" * 50000)
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + "Server: debian\r\n"
            + f"{header[0]}: {header[1]}\r\n"
            + f"Content-Length: {100000}\r\n\r\n"
            + ("x" * 100000)
        )

        client.send_request(client.create_request(method="GET", headers=[]), "200")
        self.assertFalse(client.connection_is_closed())

    @marks.Parameterize.expand(
        [
            # When tcp_mtu_probing is set, kernel tries to coalesce several
            # skb in one and send it. Resulting skb size depends on mtu size.
            # To check how Tempesta FW works with this option we use large
            # response, which contains in several skbs.
            marks.Param(
                name="large_response_tcp_mtu_probing_1500",
                option="net.ipv4.tcp_mtu_probing",
                value=2,
                mtu=1500,
            ),
            marks.Param(
                name="large_response_tcp_mtu_probing_40000",
                option="net.ipv4.tcp_mtu_probing",
                value=2,
                mtu=40000,
            ),
        ]
    )
    def test(self, name, option, value, mtu):
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")
        self.run_test_tso_gro_gso_def(client, server, self.__test, mtu, option, value)
