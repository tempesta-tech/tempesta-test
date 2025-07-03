"""Tests for client mem configuration."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

from helpers import error
from helpers.deproxy import HttpMessage
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

DEPROXY_SERVER = {
    "id": "deproxy",
    "type": "deproxy",
    "port": "8000",
    "response": "static",
    "response_content": "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n",
}


class TestConfig(tester.TempestaTest):
    """
    This class contains tests for 'client_mem' directives.
    """

    tempesta = {
        "config": """
listen 80;
"""
    }

    def __update_tempesta_config(self, client_mem_config: str):
        new_config = self.get_tempesta().config.defconfig
        self.get_tempesta().config.defconfig = new_config + client_mem_config

    @marks.Parameterize.expand(
        [
            marks.Param(name="not_present", client_mem_config="client_mem;\n"),
            marks.Param(name="to_many_args", client_mem_config="client_mem 1 3 5;\n"),
            marks.Param(name="no_attrs", client_mem_config="client_mem 1 b=3;\n"),
            marks.Param(name="value_1", client_mem_config="client_mem 11aa;\n"),
        ]
    )
    def test_invalid(self, name, client_mem_config):
        tempesta = self.get_tempesta()
        self.__update_tempesta_config(client_mem_config)
        self.oops_ignore = ["ERROR"]
        with self.assertRaises(error.ProcessBadExitStatusException):
            tempesta.start()


@marks.parameterize_class(
    [
        {"name": "Http", "clients": [DEPROXY_CLIENT]},
        {"name": "Https", "clients": [DEPROXY_CLIENT_SSL]},
        {"name": "H2", "clients": [DEPROXY_CLIENT_H2]},
    ]
)
class TestCache(tester.TempestaTest):
    tempesta = {
        "config": """
listen 80;
listen 443 proto=h2,https;

client_mem 100 1000;

server ${server_ip}:8000;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
""",
    }

    backends = [DEPROXY_SERVER]

    def test(self):
        self.start_all_services()

        srv: StaticDeproxyServer = self.get_server("deproxy")
        srv.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-Length: 13\r\n"
            + "Content-Type: text/html\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + "\r\n"
            + "<html></html>"
        )

        client = self.get_client("deproxy")
        request = client.create_request(
            method="GET",
            uri="/",
            headers=[],
        )

        client.send_request(request, expected_status_code="200")
