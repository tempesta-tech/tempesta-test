"""
On the fly reconfiguration stress test for sticky cookie scheduler.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import http
from typing import Dict, List, Optional

from framework.curl_client import CurlResponse
from helpers.control import Tempesta
from helpers.tempesta import ServerStats
from helpers.tf_cfg import cfg
from reconf.reconf_stress_base import LiveReconfStressTestCase
from run_config import CONCURRENT_CONNECTIONS, DURATION, REQUESTS_COUNT, THREADS

SRV_START = "# Sticky Cookie Settings"
SRV_AFTER_RELOAD = """
sticky {
    cookie enforce;
    secret "f00)9eR59*_/22";
    sticky_sessions;
}
"""

NGINX_CONFIG = """
pid ${pid};
worker_processes  auto;

events {
    worker_connections   1024;
    use epoll;
}

http {
    keepalive_timeout ${server_keepalive_timeout};
    keepalive_requests 1000000000;
    sendfile         on;
    tcp_nopush       on;
    tcp_nodelay      on;

    open_file_cache max=1000;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors off;

    # Fully disable log errors.
    error_log /dev/null emerg;

    # Disable access log altogether.
    access_log off;

    server {
        listen        ${server_ip}:${port};

        location / {
            return 200;
        }
        location /nginx_status {
            stub_status on;
        }
    }
}
"""

TEMPESTA_CONFIG = """
listen ${tempesta_ip}:443 proto=h2;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;

cache 0;

# Sticky Cookie Settings

sched ratio static;

srv_group default {
    server ${server_ip}:8000;
    server ${server_ip}:8001;
}

vhost app {
    proxy_pass default;
}

http_chain {
    host == "app.com" -> app;
}
"""


class TestGraceShutdownLiveReconf(LiveReconfStressTestCase):
    """
    This class tests on-the-fly reconfig of Tempesta for sticky cookie.
    """

    backends_count = 2

    backends = [
        {
            "id": f"nginx_800{step}",
            "type": "nginx",
            "port": f"800{step}",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        }
        for step in range(backends_count)
    ]

    clients = [
        {
            "id": "curl",
            "type": "curl",
            "http2": True,
            "addr": "${tempesta_ip}:443",
        },
        {
            "id": "h2load",
            "type": "external",
            "binary": "h2load",
            "ssl": True,
            "cmd_args": (
                " https://${tempesta_ip}:443/"
                f" --clients {CONCURRENT_CONNECTIONS}"
                f" --threads {THREADS}"
                f" --max-concurrent-streams {REQUESTS_COUNT}"
                f" --duration {DURATION}"
            ),
        },
    ]

    tempesta = {
        "config": TEMPESTA_CONFIG,
    }

    def test_reconf_on_the_fly_for_sticky_cookie_sched(self) -> None:
        """Test of sticky sessions to a server group."""
        # launch all services except clients
        self.start_all_services(client=False)
        tempesta: Tempesta = self.get_tempesta()
        client = self.get_client("h2load")

        # check Tempesta config (before reload)
        self._check_start_config(tempesta, SRV_START, SRV_AFTER_RELOAD)

        # perform curl request
        response = self.make_curl_request("curl", headers={"Host": "app.com"})
        self.assertEqual(response.status, http.HTTPStatus.OK)

        # launch h2load client - HTTP/2 benchmarking tool
        client.start()

        # get statistics
        stats_srvs: List[ServerStats] = [
            ServerStats(tempesta, "default", cfg.get("Server", "ip"), port) for port in (8000, 8001)
        ]

        # check servers statistics
        for srv in stats_srvs:
            self.assertFalse(srv.total_pinned_sessions)

        # config Tempesta change,
        # reload Tempesta, check logs,
        # and check config Tempesta after reload
        self.reload_config(
            tempesta,
            SRV_START,
            SRV_AFTER_RELOAD,
        )

        # perform `init` request
        response = self.make_curl_request("curl")
        self.assertEqual(response.status, http.HTTPStatus.FOUND)
        self.assertIn("__tfw", response.headers["set-cookie"])

        # perform curl request
        cookie_header = {"Cookie": response.headers["set-cookie"]}
        response = self.make_curl_request("curl", headers=cookie_header)
        self.assertEqual(response.status, http.HTTPStatus.OK)

        # check servers statistics
        nginx_8000 = ServerStats(tempesta, "default", cfg.get("Server", "ip"), 8000)
        nginx_8001 = ServerStats(tempesta, "default", cfg.get("Server", "ip"), 8001)
        self.assertEqual(nginx_8000.total_pinned_sessions, 0)
        self.assertEqual(nginx_8001.total_pinned_sessions, 1)

        # # h2load stop
        self.wait_while_busy(client)
        client.stop()
        self.assertEqual(client.returncode, 0)

    def make_curl_request(
        self,
        curl_client_id: str,
        headers: Dict[str, str] = None,
    ) -> Optional[CurlResponse]:
        """
        Make `curl` request.

        Args:
            curl_client_id (str): Curl client id to make request for.
            headers: A dict mapping keys to the corresponding query header values.
                Defaults to None.

        Returns:
            The object of the CurlResponse class - parsed cURL response or None.
        """
        curl = self.get_client(curl_client_id)

        if headers is None:
            headers = {}

        if headers:
            for key, val in headers.items():
                curl.headers[key] = val

        curl.start()
        self.wait_while_busy(curl)
        self.assertEqual(
            0,
            curl.returncode,
            msg=(f"Curl return code is not 0. Received - {curl.returncode}."),
        )
        curl.stop()
        return curl.last_response


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
