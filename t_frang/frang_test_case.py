"""Basic file for frang functional tests."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"


from framework import tester
from framework.deproxy_client import DeproxyClient
from helpers import dmesg

DELAY = 0.125


class FrangTestCase(tester.TempestaTest):
    """Base class for frang tests."""

    clients = [
        {
            "id": "deproxy-1",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    tempesta_template = {
        "config": """
cache 0;
listen 80;
listen 443 proto=h2;
frang_limits {
    %(frang_config)s
    ip_block off;
}
server ${server_ip}:8000;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;

block_action attack reply;
""",
    }

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n"
            ),
        },
    ]

    timeout = 0.5

    def setUp(self):
        super().setUp()
        self.klog = dmesg.DmesgFinder(ratelimited=False)
        self.assert_msg = "Expected nums of warnings in `journalctl`: {exp}, but got {got}"

    def set_frang_config(self, frang_config: str):
        self.tempesta["config"] = self.tempesta_template["config"] % {
            "frang_config": frang_config,
        }
        self.setUp()
        self.start_all_services(client=False)

    def base_scenario(
        self, frang_config: str, requests: list, disable_hshc: bool = False
    ) -> DeproxyClient:
        self.set_frang_config(
            "\n".join(
                [frang_config] + (["http_strict_host_checking false;"] if disable_hshc else [])
            )
        )

        client = self.get_client("deproxy-1")
        client.parsing = False
        client.start()
        client.make_requests(requests)
        client.wait_for_response(3)
        return client

    def check_response(self, client, status_code: str, warning_msg: str):
        self.assertIsNotNone(client.last_response, "Deproxy client has lost response.")
        for response in client.responses:
            self.assertEqual(response.status, status_code, "HTTP response status codes mismatch.")

            if status_code == "200":
                self.assertFalse(client.connection_is_closed())
                self.assertFrangWarning(warning=warning_msg, expected=0)
            else:
                self.assertTrue(client.wait_for_connection_close(self.timeout))
                self.assertFrangWarning(warning=warning_msg, expected=1)

    def assertFrangWarning(self, warning: str, expected: int):
        warning_count = self.klog.warn_count(warning)
        self.assertEqual(
            warning_count, expected, self.assert_msg.format(exp=expected, got=warning_count)
        )


class H2Config:
    clients = [
        {
            "id": "deproxy-1",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        },
    ]

    post_request = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "POST"),
    ]

    get_request = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
    ]
