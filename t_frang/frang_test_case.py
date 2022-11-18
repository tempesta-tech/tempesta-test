"""Basic file for frang functional tests."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
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
frang_limits {
    %(frang_config)s
    ip_block off;
}
server ${server_ip}:8000;
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

    def base_scenario(self, frang_config: str, requests: list) -> DeproxyClient:
        self.set_frang_config(frang_config)

        client = self.get_client("deproxy-1")
        client.parsing = False
        client.start()
        for request in requests:
            client.make_request(request)
        client.wait_for_response(1)
        return client

    def check_response(self, client, status_code: str, warning_msg: str):
        for response in client.responses:

            self.assertIsNotNone(response, "Deproxy client has lost response.")
            self.assertEqual(response.status, status_code, "HTTP response status codes mismatch.")

            if status_code == "200":
                self.assertFalse(client.connection_is_closed())
                self.assertFrangWarning(warning=warning_msg, expected=0)
            else:
                self.assertTrue(client.connection_is_closed())
                self.assertFrangWarning(warning=warning_msg, expected=1)

    def assertFrangWarning(self, warning: str, expected: int):
        warning_count = self.klog.warn_count(warning)
        self.assertEqual(
            warning_count, expected, self.assert_msg.format(exp=expected, got=warning_count)
        )
