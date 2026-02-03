"""
On the fly reconfiguration stress test.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework.helpers.dmesg import limited_rate_on_tempesta_node
from framework.helpers.tf_cfg import cfg
from tests.reconf.reconf_stress import LiveReconfStressTestBase

SOCKET_START = f"{cfg.get('Tempesta', 'ip')}:443"
SOCKET_AFTER_RELOAD = f"{cfg.get('Tempesta', 'ip')}:4433"
STATUS_OK = "200"

TEMPESTA_CONFIG = """
listen ${tempesta_ip}:443 proto=h2;
frang_limits {http_strict_host_checking false;}
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
max_concurrent_streams 10000;

cache 0;
server ${server_ip}:8000;
"""


class TestLiveReconf(LiveReconfStressTestBase):
    dbg_msg = "Error for curl"

    curl_clients = [
        {
            "id": "curl-%s" % count,
            "type": "external",
            "binary": "curl",
            "ssl": True,
            "cmd_args": ("-Ikf --http2 https://${tempesta_ip}:%s/" % port),
        }
        for count, port in enumerate(("443", "4433"))
    ]

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": ("HTTP/1.1 200 OK\r\n" "Content-length: 0\r\n" "\r\n"),
        },
    ]

    tempesta = {
        "config": TEMPESTA_CONFIG,
    }

    def setUp(self) -> None:
        self.clients.extend(self.curl_clients)
        super().setUp()
        self.addCleanup(self.cleanup_clients)

    def cleanup_clients(self) -> None:
        for client in self.curl_clients:
            self.clients.remove(client)

    @limited_rate_on_tempesta_node
    def test_stress_reconfig_on_the_fly(self) -> None:
        """Test Tempesta for change config on the fly."""
        self.disable_deproxy_auto_parser()
        # launch all services except clients
        self.start_all_services(client=False)

        # start config Tempesta check (before reload)
        self._check_start_tfw_config(
            SOCKET_START,
            SOCKET_AFTER_RELOAD,
        )

        # launch h2load
        client = self.get_client("h2load")
        client.start()

        # sending curl requests before reconfig Tempesta
        response = self.make_curl_request("curl-0")
        self.assertIn(STATUS_OK, response, msg=self.dbg_msg)

        # check reload socket not in Tempesta config
        self.check_non_working_socket("curl-1")

        # config Tempesta change,
        # reload, and check after reload
        self.reload_tfw_config(
            SOCKET_START,
            SOCKET_AFTER_RELOAD,
        )

        # sending curl requests after reconfig Tempesta
        response = self.make_curl_request("curl-1")
        self.assertIn(STATUS_OK, response, msg=self.dbg_msg)

        # check start socket not in Tempesta config
        self.check_non_working_socket("curl-0")

        # h2load stop
        self.wait_while_busy(client)
        client.stop()
        self.assertNotIn(" 0 2xx, ", client.response_msg)

    def check_non_working_socket(
        self,
        curl_client_id: str,
    ) -> None:
        """
        Check that socket is not working.

        Args:
            socket: Socket for checking.
        """
        self.assertRaises(
            Exception,
            self.make_curl_request(curl_client_id),
        )


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
