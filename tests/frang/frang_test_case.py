"""Basic file for frang functional tests."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"


from typing import Union  # TODO: use | instead when we move to python3.10

import run_config
from framework.deproxy.deproxy_client import DeproxyClient, DeproxyClientH2
from framework.helpers import dmesg, tf_cfg
from framework.test_suite import tester

# used to prevent burst
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
        {
            "id": "ratechecker",
            "type": "external",
            "binary": "ratecheck",
            "ssl": True,
            "cmd_args": "",
        },
    ]

    tempesta = {
        "config": """
cache 0;
listen 80;
listen 81;
listen 443 proto=h2;
frang_limits {
    %(frang_config)s
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

    # waiting for dmesg
    timeout = 0.5

    def setUp(self):
        super().setUp()
        self.klog = dmesg.DmesgFinder(disable_ratelimit=True)
        self.assert_msg = "Expected nums of warnings in `journalctl`: {exp}, but got {got}"
        # Cleanup part
        self.addCleanup(self.cleanup_klog)

    def cleanup_klog(self):
        if hasattr(self, "klog"):
            del self.klog

    # TODO: rename to set_frang_cfg_and_start
    def set_frang_config(self, frang_config: str):
        self.get_tempesta().config.set_defconfig(
            self.get_tempesta().config.defconfig
            % {
                "frang_config": frang_config,
            }
        )
        self.start_all_services(client=False)

    def base_scenario(
        self, frang_config: str, requests: list, disable_hshc: bool = False, huffman: bool = True
    ) -> DeproxyClient:
        self.set_frang_config(
            "\n".join(
                [frang_config] + (["http_strict_host_checking false;"] if disable_hshc else [])
            )
        )

        client = self.get_client("deproxy-1")
        client.parsing = False
        client.start()
        for request in requests:
            if isinstance(client, DeproxyClientH2):
                client.make_request(request, huffman=huffman)
            else:
                client.make_request(request)
            client.wait_for_response(3)
        return client

    def _check_frang_warning(self, client, status_code: str, warning_msg: str):
        if status_code == "200":
            self.assertFalse(client.connection_is_closed())
            self.assertFrangWarning(warning=warning_msg, expected=0)
        else:
            self.assertTrue(client.wait_for_connection_close())
            self.assertFrangWarning(warning=warning_msg, expected=1)

    def check_last_response(self, client, status_code: str, warning_msg: str):
        """
        We can't be sure that client receive error response in case of TCP
        segmentation, because if we receive some data from client after
        socket closing, kernel send TCP RST to client.
        """
        if not run_config.TCP_SEGMENTATION or status_code == "200":
            self.assertIsNotNone(client.last_response, "Deproxy client has lost response.")
            self.assertEqual(
                client.last_response.status, status_code, "HTTP response status codes mismatch."
            )
        self._check_frang_warning(client, status_code, warning_msg)

    def check_response(self, client, status_code: str, warning_msg: str):
        """
        We can't be sure that client receive error response in case of TCP
        segmentation, because if we receive some data from client after
        socket closing, kernel send TCP RST to client.
        """
        if not run_config.TCP_SEGMENTATION or status_code == "200":
            self.assertIsNotNone(client.last_response, "Deproxy client has lost response.")
            for response in client.responses:
                self.assertEqual(
                    response.status, status_code, "HTTP response status codes mismatch."
                )

        self._check_frang_warning(client, status_code, warning_msg)

    def check_connections(self, clients, warning: str, resets_expected: Union[int, range]):
        warns_occured = self.assertFrangWarning(warning, resets_expected)
        reset_conn_n = sum(c.reset_conn_n for c in clients)
        self.assertEqual(reset_conn_n, warns_occured)

    def assertFrangWarning(self, warning: str, expected: Union[int, range]):
        if type(expected) is range:
            found_greater_eq = self.klog.find(warning, cond=dmesg.amount_greater_eq(expected.start))
            amount = len(self.klog.log_findall(warning))
            self.assertTrue(
                found_greater_eq,
                f"Amount of '{warning}' warnings in dmesg is less then {expected.start}: {amount}",
            )

            # [start, stop], not [start, stop)
            self.assertLessEqual(
                amount,
                expected.stop,
                f"Amount of '{warning}' warnings in dmesg is more then {expected.stop}: {amount}",
            )
        else:
            self.assertTrue(self.klog.find(warning, cond=dmesg.amount_equals(expected)), expected)

        return len(self.klog.log_findall(warning))

    def run_rate_check(self, client, conn_n, is_tls):
        tempesta_ip = tf_cfg.cfg.get("Tempesta", "ip")
        ctype = "tls" if is_tls else "tcp"
        client.options = [
            f" -address {tempesta_ip}:443 -connections {conn_n} -sni tempesta-tech.com -conn_type {ctype}"
        ]
        client.start()
        self.wait_while_busy(client)
        client.stop()
        self.assertEqual(0, client.returncode)


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
