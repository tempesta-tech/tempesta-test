"""
On the fly reconfiguration stress test for http scheduler.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework.external_client import ExternalTester
from helpers.tf_cfg import cfg
from t_reconf.reconf_stress import LiveReconfStressTestBase

HTTP_RULES_START = 'uri == "/alternate" -> block;'
HTTP_RULES_AFTER_RELOAD = 'uri == "/alternate" -> alternate;'
STATUS_OK = "200"
STATUS_FORBIDDEN = "403"
VHOSTS = ("origin", "alternate")
TEMPESTA_IP = cfg.get("Tempesta", "ip")

TEMPESTA_CONFIG = """
listen 443 proto=h2;

srv_group origin {
    server ${server_ip}:8080;
}

srv_group alternate {
    server ${server_ip}:8081;
}

vhost origin{
    proxy_pass origin;
}

vhost alternate{
    proxy_pass alternate;
}

tls_match_any_server_name;
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
max_concurrent_streams 2147483647;

cache 0;
block_action attack reply;

http_chain {
    uri == "/origin" -> origin;
    uri == "/alternate" -> block;
}
"""


class TestSchedHttpLiveReconf(LiveReconfStressTestBase):
    """
    This class tests on-the-fly reconfig of Tempesta for the http scheduler.
    This test covers the case of modify HTTPtables rules to change load
    distribution across virtual hosts for to update load balancing rules
    on the fly.
    """

    dbg_msg = "Error for curl"

    curl_clients = [
        {
            "id": "curl-%s-h2" % vhost,
            "type": "external",
            "binary": "curl",
            "ssl": True,
            "cmd_args": "-Ikf --http2 https://${tempesta_ip}:443/%s" % vhost,
        }
        for vhost in VHOSTS
    ]

    backends = [
        {
            "id": f"srv-{vhost}",
            "type": "deproxy",
            "port": f"808{count}",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                f"From: /{vhost}\r\n"
                "Server: debian\r\n"
                "Content-length: 0\r\n"
                "\r\n"
            ),
        }
        for count, vhost in enumerate(VHOSTS)
    ]

    tempesta = {"config": TEMPESTA_CONFIG}

    def setUp(self) -> None:
        self.clients.extend(self.curl_clients)
        super().setUp()
        self.addCleanup(self.cleanup_clients)
        self.addCleanup(self.cleanup_client_cmd_opt)

    def cleanup_clients(self) -> None:
        for client in self.curl_clients:
            self.clients.remove(client)

    def cleanup_client_cmd_opt(self) -> None:
        client = self.get_client("h2load")
        client.options[0] = self._change_uri_cmd_opt(client)

    def test_reconfig_on_the_fly_for_sched_http(self) -> None:
        """Test Tempesta for change config on the fly."""
        # launch all services except clients
        self.start_all_services(client=False)

        # start config Tempesta check (before reload)
        self._check_start_tfw_config(
            HTTP_RULES_START,
            HTTP_RULES_AFTER_RELOAD,
        )

        # launch H2Load
        client_h2 = self.get_client("h2load")
        client_h2.options[0] = self._change_uri_cmd_opt(client_h2, VHOSTS[0])
        client_h2.start()

        # sending curl requests before reconfig Tempesta
        response = self.make_curl_request("curl-origin-h2")
        self.assertIn(STATUS_OK, response, msg=self.dbg_msg)

        response = self.make_curl_request("curl-alternate-h2")
        self.assertIn(STATUS_FORBIDDEN, response, msg=self.dbg_msg)

        # config Tempesta change,
        # reload, and check after reload
        self.reload_tfw_config(
            HTTP_RULES_START,
            HTTP_RULES_AFTER_RELOAD,
        )

        # additional check config Tempesta after reload
        self._check_tfw_config_after_reload()

        # sending curl requests after reconfig Tempesta
        for client in [client["id"] for client in self.curl_clients]:
            response = self.make_curl_request(client)
            self.assertIn(STATUS_OK, response, msg=self.dbg_msg)

        # H2Load stop
        self.wait_while_busy(client_h2)
        client_h2.stop()

    def _change_uri_cmd_opt(self, client: ExternalTester, path: str = None) -> str:
        """Changing the uri option in the options list of client.

        Args:
            client: instance of ExternalTester object.
            path: string object representing a part of uri.

        Returns:
            String object representing a modified list of options.

        """
        uri = f" https://{TEMPESTA_IP}:443/"
        if path:
            opts = client.options[0].replace(uri, uri + path)
            return opts
        opts = client.options[0].split()
        opts[0] = uri
        return " ".join(opts)

    def _check_tfw_config_after_reload(self) -> None:
        """Checking the Tempesta configuration after reload."""
        tempesta = self.get_tempesta()

        for vhost in VHOSTS:
            self.assertIn(
                f'uri == "/{vhost}" -> {vhost};',
                tempesta.config.get_config(),
            )


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
