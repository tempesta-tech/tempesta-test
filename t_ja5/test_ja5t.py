"""Functional tests of ja5 filtration."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework.deproxy_client import DeproxyClientH2
from framework.deproxy_server import StaticDeproxyServer
from test_suite import marks, tester

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


@marks.parameterize_class(
    [
        {"name": "Http", "clients": [DEPROXY_CLIENT_SSL]},
        {"name": "H2", "clients": [DEPROXY_CLIENT_H2]},
    ]
)
class TestJa5t(tester.TempestaTest):
    """This class contains checks for tempesta ja5 filtration."""

    tempesta = {
        "config": """
listen 443 proto=h2,https;

server ${server_ip}:8000;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
""",
    }

    backends = [DEPROXY_SERVER]

    @marks.Parameterize.expand(
        [
            marks.Param(name="no_hash", tempesta_ja5_config="", expected_response=True),
            marks.Param(
                name="hash_not_for_client",
                tempesta_ja5_config="""
					ja5t {
						hash deadbeef 10 1000;
					}
				""",
                expected_response=True,
            ),
            marks.Param(
                name="hash_for_client_not_block",
                tempesta_ja5_config="""
					ja5t {
						hash 66cb9fd8d4250000 1 10;
					}
				""",
                expected_response=True,
            ),
            marks.Param(
                name="hash_for_client_block_by_conn",
                tempesta_ja5_config="""
					ja5t {
						hash 66cb9fd8d4250000 0 10;
						hash 66cb8f00d4250002 0 10;
					}
				""",
                expected_response=False,
            ),
            marks.Param(
                name="hash_for_client_block_by_rate",
                tempesta_ja5_config="""
					ja5t {
						hash 66cb9fd8d4250000 1 0;
						hash 66cb8f00d4250002 1 0;
					}
				""",
                expected_response=False,
            ),
        ]
    )
    def test(self, name, tempesta_ja5_config: str, expected_response: bool):
        """Update tempesta config. Send many identical requests and checks cache operation."""
        tempesta: Tempesta = self.get_tempesta()
        tempesta.config.defconfig += tempesta_ja5_config

        self.start_all_services()

        srv: StaticDeproxyServer = self.get_server("deproxy")
        srv.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-Length: 13\r\n"
            + "Content-Type: text/html\r\n"
            + "\r\n"
            + "<html></html>"
        )

        client = self.get_client("deproxy")
        request = client.create_request(method="GET", uri="/", headers=[])

        client.make_request(request)
        if expected_response:
            self.assertTrue(client.wait_for_response())
            self.assertTrue(client.last_response.status, "200")
        else:
            self.assertFalse(client.wait_for_response())
