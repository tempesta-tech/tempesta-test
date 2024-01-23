"""
On the fly reconfiguration stress test for http scheduler.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework.external_client import ExternalTester
from helpers.control import Tempesta
from reconf.reconf_stress_base import LiveReconfStressTestCase
from run_config import CONCURRENT_CONNECTIONS, DURATION, REQUESTS_COUNT, THREADS

HTTP_RULES_START = 'uri == "/alternate" -> block;'
HTTP_RULES_AFTER_RELOAD = 'uri == "/alternate" -> alternate;'
STATUS_OK = "200"
STATUS_FORBIDDEN = "403"
ERR_MSG = "Error for curl"
VHOSTS = ("origin", "alternate")

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

cache 0;
block_action attack reply;

http_chain {
    uri == "/origin" -> origin;
    uri == "/alternate" -> block;
}
"""


class TestSchedHttpLiveReconf(LiveReconfStressTestCase):
    """
    This class tests on-the-fly reconfig of Tempesta for the http scheduler.
    This test covers the case of modify HTTPtables rules to change load
    distribution across virtual hosts for to update load balancing rules
    on the fly.
    """

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

    clients = [
        {
            "id": "curl-%s-h2" % vhost,
            "type": "external",
            "binary": "curl",
            "ssl": True,
            "cmd_args": "-Ikf --http2 https://${tempesta_ip}:443/%s" % vhost,
        }
        for vhost in VHOSTS
    ]

    clients.append(
        {
            "id": "h2load",
            "type": "external",
            "binary": "h2load",
            "ssl": True,
            "cmd_args": (
                " https://${tempesta_ip}/origin"
                f" --clients {CONCURRENT_CONNECTIONS}"
                f" --threads {THREADS}"
                f" --max-concurrent-streams {REQUESTS_COUNT}"
                f" --duration {DURATION}"
            ),
        },
    )

    tempesta = {"config": TEMPESTA_CONFIG}

    def test_reconfig_on_the_fly_for_sched_http(self) -> None:
        """Test Tempesta for change config on the fly."""
        # launch all services except clients and getting Tempesta instance
        self.start_all_services(client=False)
        tempesta: Tempesta = self.get_tempesta()

        # start config Tempesta check (before reload)
        self._check_start_config(
            tempesta,
            HTTP_RULES_START,
            HTTP_RULES_AFTER_RELOAD,
        )

        # launch H2Load
        client_h2: ExternalTester = self.get_client("h2load")
        client_h2.start()
        self.wait_while_busy(client_h2)

        # sending curl requests before reconfig Tempesta
        response = self.make_curl_request("curl-origin-h2")
        self.assertIn(STATUS_OK, response, msg=ERR_MSG)

        response = self.make_curl_request("curl-alternate-h2")
        self.assertIn(STATUS_FORBIDDEN, response, msg=ERR_MSG)

        # config Tempesta change,
        # reload Tempesta, check logs,
        # and check config Tempesta after reload
        self.reload_config(
            tempesta,
            HTTP_RULES_START,
            HTTP_RULES_AFTER_RELOAD,
        )

        # additional check config Tempesta after reload
        self._check_config_after_reload(tempesta)

        # sending curl requests after reconfig Tempesta
        for client in self.clients[:2]:
            response = self.make_curl_request(client["id"])
            self.assertIn(STATUS_OK, response, msg=ERR_MSG)

        # H2Load stop
        client_h2.stop()

        self.assertEqual(client_h2.returncode, 0)
        self.assertNotIn(" 0 2xx, ", client_h2.response_msg)

    def _check_config_after_reload(self, tempesta: Tempesta) -> None:
        """
        Checking the Tempesta configuration after reload.

        Args:
            tempesta: object of working Tempesta

        """
        for vhost in VHOSTS:
            self.assertIn(
                f'uri == "/{vhost}" -> {vhost};',
                tempesta.config.get_config(),
            )


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
