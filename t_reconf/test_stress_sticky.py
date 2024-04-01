"""
On the fly reconfiguration stress test for sticky cookie scheduler.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import http

from helpers.tempesta import ServerStats
from helpers.tf_cfg import cfg
from t_reconf.reconf_stress import LiveReconfStressTestBase

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
max_concurrent_streams 2147483647;

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


class TestGraceShutdownLiveReconf(LiveReconfStressTestBase):
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

    tempesta = {
        "config": TEMPESTA_CONFIG,
    }

    def test_reconf_on_the_fly_for_sticky_cookie_sched(self) -> None:
        """Test of sticky sessions to a server group."""
        # launch all services except clients
        self.start_all_services(client=False)
        tempesta = self.get_tempesta()
        client = self.get_client("h2load")

        # check Tempesta config (before reload)
        self._check_start_tfw_config(SRV_START, SRV_AFTER_RELOAD)

        # perform curl request
        response = self.make_curl_client_request("curl", headers={"Host": "app.com"})
        self.assertEqual(response.status, http.HTTPStatus.OK)

        # launch h2load
        client.options[0] += ' --header ":authority: app.com"'
        client.start()

        # get statistics
        stats_srvs: list[ServerStats] = [
            ServerStats(tempesta, "default", cfg.get("Server", "ip"), port) for port in (8000, 8001)
        ]

        # check servers statistics
        for srv in stats_srvs:
            self.assertFalse(srv.total_pinned_sessions)

        # config Tempesta change,
        # reload, and check after reload
        self.reload_tfw_config(
            SRV_START,
            SRV_AFTER_RELOAD,
        )

        # perform `init` request
        response = self.make_curl_client_request("curl")
        self.assertEqual(response.status, http.HTTPStatus.FOUND)
        self.assertIn("__tfw", response.headers["set-cookie"])

        # perform curl request
        cookie_header = {"Cookie": response.headers["set-cookie"]}
        response = self.make_curl_client_request("curl", headers=cookie_header)
        self.assertEqual(response.status, http.HTTPStatus.OK)

        # check servers statistics
        nginx_8000 = ServerStats(tempesta, "default", cfg.get("Server", "ip"), 8000)
        nginx_8001 = ServerStats(tempesta, "default", cfg.get("Server", "ip"), 8001)
        self.assertEqual(nginx_8000.total_pinned_sessions, 0)
        self.assertEqual(nginx_8001.total_pinned_sessions, 1)

        # # h2load stop
        self.wait_while_busy(client)
        client.stop()


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
