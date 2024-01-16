"""
On the fly reconfiguration stress test for http scheduler.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester
from framework.external_client import ExternalTester
from helpers import tf_cfg
from helpers.control import Tempesta

# Number of open connections
CONCURRENT_CONNECTIONS = int(tf_cfg.cfg.get("General", "concurrent_connections"))
# Number of threads to use for wrk and h2load tests
THREADS = int(tf_cfg.cfg.get("General", "stress_threads"))

# Number of requests to make
REQUESTS_COUNT = int(tf_cfg.cfg.get("General", "stress_requests_count"))
# Time to wait for single request completion
DURATION = int(tf_cfg.cfg.get("General", "duration"))

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


class TestSchedHttpReconfStress(tester.TempestaTest):
    """
    This class tests on-the-fly reconfig of Tempesta for the http scheduler.
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
        self._check_start_config(tempesta)

        # launch H2Load
        client_h2: ExternalTester = self.get_client("h2load")
        client_h2.start()
        self.wait_while_busy(client_h2)

        # sending curl requests before reconfig Tempesta
        response = self.make_curl_request("curl-origin-h2")
        self.assertIn(STATUS_OK, response, msg=ERR_MSG)

        response = self.make_curl_request("curl-alternate-h2")
        self.assertIn(STATUS_FORBIDDEN, response, msg=ERR_MSG)

        # config change and reload Tempesta
        tempesta.config.defconfig = tempesta.config.defconfig.replace(
            HTTP_RULES_START,
            HTTP_RULES_AFTER_RELOAD,
        )
        tempesta.reload()

        # check logs Tempesta after reload
        self._check_tfw_log()

        # check config Tempesta after reload
        self._check_config_after_reload(tempesta)

        # sending curl requests after reconfig Tempesta
        for client in self.clients[:2]:
            response = self.make_curl_request(client["id"])
            self.assertIn(STATUS_OK, response, msg=ERR_MSG)

        # H2Load stop
        client_h2.stop()

        self.assertEqual(client_h2.returncode, 0)
        self.assertNotIn(" 0 2xx, ", client_h2.response_msg)

    def make_curl_request(self, curl_client_id: str) -> str:
        """
        Make `curl` request.

        Args:
            curl_client_id (str): curl client id to make request for

        Returns:
            str: server response to the request as string
        """
        client: ExternalTester = self.get_client(curl_client_id)
        client.start()
        self.wait_while_busy(client)
        self.assertEqual(
            0,
            client.returncode,
            msg=(f"Curl return code is not 0. Received - {client.returncode}."),
        )
        client.stop()
        return client.response_msg

    def _check_tfw_log(self) -> None:
        """Checking the Tempesta log."""
        self.oops.update()
        self.assertFalse(len(self.oops.log_findall("ERROR")))
        self.assertIn(
            b"[tempesta fw] Live reconfiguration of Tempesta.",
            self.oops.log,
        )

    def _check_start_config(self, tempesta: Tempesta) -> None:
        """
        Checking the Tempesta start configuration.

        Args:
            tempesta: object of working Tempesta

        """
        self.assertIn(
            HTTP_RULES_START,
            tempesta.config.get_config(),
        )

        self.assertNotIn(
            HTTP_RULES_AFTER_RELOAD,
            tempesta.config.get_config(),
        )

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
