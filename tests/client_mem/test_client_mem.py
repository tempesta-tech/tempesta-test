"""Tests for client mem configuration."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import run_config
from framework.helpers import error
from framework.test_suite import marks, tester

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

DEPROXY_SERVER = {
    "id": "deproxy",
    "type": "deproxy",
    "port": "8000",
    "response": "static",
    "response_content": "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n",
}


class TestClientMemBase(tester.TempestaTest):
    def update_tempesta_config(self, client_mem_config: str):
        new_config = self.get_tempesta().config.defconfig
        self.get_tempesta().config.defconfig = new_config + client_mem_config


class TestClientMemConfig(TestClientMemBase):
    """
    This class contains tests for 'client_mem' directives.
    """

    tempesta = {
        "config": """
listen 80;
"""
    }

    @marks.Parameterize.expand(
        [
            marks.Param(name="not_present", client_mem_config="client_mem;\n"),
            marks.Param(name="to_many_args", client_mem_config="client_mem 1 3 5;\n"),
            marks.Param(name="no_attrs", client_mem_config="client_mem 1 b=3;\n"),
            marks.Param(name="value_1", client_mem_config="client_mem 11aa;\n"),
            marks.Param(name="soft_is_greater_then_hard", client_mem_config="client_mem 10 1;\n"),
        ]
    )
    def test_invalid(self, name, client_mem_config):
        tempesta = self.get_tempesta()
        self.update_tempesta_config(client_mem_config)
        self.oops_ignore = ["ERROR"]
        with self.assertRaises(error.ProcessBadExitStatusException):
            tempesta.start()


@marks.parameterize_class(
    [
        {
            "name": "Http",
            "clients": [DEPROXY_CLIENT],
            "expect_response": True,
            "client_mem": "client_mem 10000 20000;\n",
        },
        {
            "name": "Https",
            "clients": [DEPROXY_CLIENT_SSL],
            "expect_response": True,
            "client_mem": "client_mem 10000 20000;\n",
        },
        {
            "name": "H2",
            "clients": [DEPROXY_CLIENT_H2],
            "expect_response": False,
            "client_mem": "client_mem 20000 40000;\n",
        },
    ]
)
class TestBlockByMemExceeded(TestClientMemBase):
    tempesta = {
        "config": """
listen 80;
listen 443 proto=h2,https;

server ${server_ip}:8000;

block_action attack reply;
block_action error reply;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
""",
    }

    backends = [DEPROXY_SERVER]
    expect_response = None

    def test_request(self):
        self.update_tempesta_config(self.client_mem)
        self.start_all_services()

        client = self.get_client("deproxy")
        request = client.create_request(
            method="POST", uri="/", headers=[("Content-Length", "10000")], body="a" * 10000
        )

        client.make_request(request)
        if self.expect_response:
            self.assertTrue(client.wait_for_response())
            self.assertTrue(client.last_response.status, "403")
        """
        For http2 connection Tempesta FW adjust memory on
        frame level, so connection will be closed with
        TCP RST without any response
        """
        self.assertTrue(client.wait_for_connection_close())

    def test_response(self):
        self.update_tempesta_config(self.client_mem)
        self.start_all_services()

        srv: StaticDeproxyServer = self.get_server("deproxy")
        srv.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Content-Length: 10000\r\n"
            + "Content-Type: text/html\r\n"
            + "\r\n"
            + "a" * 10000
        )

        client = self.get_client("deproxy")
        request = client.create_request(
            method="GET",
            uri="/",
            headers=[],
        )

        client.make_request(request)
        if not run_config.TCP_SEGMENTATION:
            self.assertTrue(client.wait_for_response())
            self.assertTrue(client.last_response.status, "403")
        self.assertTrue(client.wait_for_connection_close())


class TestBlockByMemExceededByPing(tester.TempestaTest):
    tempesta = {
        "config": """
listen 443 proto=h2;

server ${server_ip}:8000;

client_mem 500 1000;
block_action attack reply;
block_action error reply;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
""",
    }

    clients = [DEPROXY_CLIENT_H2]

    backends = [DEPROXY_SERVER]

    def _ping(self, client):
        client.h2_connection.ping(opaque_data=b"\x00\x01\x02\x03\x04\x05\x06\x07")
        client.send_bytes(client.h2_connection.data_to_send())
        client.h2_connection.clear_outbound_data_buffer()

    def test(self):
        self.start_all_services()

        ping_count = 10000

        client = self.get_client("deproxy")
        for _ in range(0, ping_count):
            self._ping(client)

        self.assertTrue(client.wait_for_connection_close())


class TestSeveralClientsWithSmallLrusize(tester.TempestaTest):
    tempesta = {
        "config": """
listen 443 proto=h2,https;

server ${server_ip}:8000;

client_lru_size 1;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
""",
    }

    clients = [
        {
            "id": f"deproxy-interface-{id_}",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "interface": True,
            "ssl": True,
        }
        for id_ in range(3)
    ]

    backends = [DEPROXY_SERVER]

    @staticmethod
    def make_resp(body):
        return "HTTP/1.1 200 OK\r\n" "Content-Length: " + str(len(body)) + "\r\n\r\n" + body

    def test_all_clients_active(self):
        self.start_all_services()
        server = self.get_server("deproxy")

        server.set_response(self.make_resp("x" * 10000))

        for id_ in range(3):
            client = self.get_client(f"deproxy-interface-{id_}")
            client.start()

        for id_ in range(3):
            client = self.get_client(f"deproxy-interface-{id_}")
            for i in range(10):
                client.make_request("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                server.wait_for_requests(id_ * 10 + i)
