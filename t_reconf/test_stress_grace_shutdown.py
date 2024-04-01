"""
On the fly reconfiguration stress test for grace shutdown time.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import http

from helpers.tempesta import ServerStats
from helpers.tf_cfg import cfg
from t_reconf.reconf_stress import LiveReconfStressTestBase

SRV_GRP_START = "server 127.0.0.3:8001;"
SRV_GRP_AFTER_RELOAD = "#"

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

sticky {
    cookie enforce;
    secret "f00)9eR59*_/22";
    sticky_sessions;
}

grace_shutdown_time 10;

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
    """This class tests on-the-fly reconfig of Tempesta for grace shutdown.

    When the on-the-fly reconfiguration is requested a removed backend server remain
    used by Tempesta until there is new active sessions pinned to the server.
    The grace_shutdown_time configuration option specifies maximum time limit in seconds
    to wait for sessions to close before all connections to the server are terminated.
    If the grace timeout is not set (defaults), then all the connections
    to the removed server are terminated immediately on reconfiguration.

    Stages of testing:
    1) Create an active session (sticky cookies) on one of the two servers.
    2) Remove the server with active session from the Tempesta configuration and reload Tempesta.
    3) Check that after reload Tempesta does not break connection with the server
    with active session removed from Tempesta configuration and continues to send requests to it.
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

    def test_reconf_on_the_fly_for_grace_shutdown(self) -> None:
        """Test of grace shutdown to a server group."""
        # 1
        # launch all services except clients
        self.start_all_services(client=False)
        tempesta = self.get_tempesta()
        client = self.get_client("h2load")

        # check Tempesta config (before reload)
        self._check_start_tfw_config(SRV_GRP_START, SRV_GRP_AFTER_RELOAD)

        # perform `init` request
        response = self.make_curl_client_request("curl", headers={"Host": "app.com"})
        self.assertEqual(response.status, http.HTTPStatus.FOUND)
        self.assertIn("__tfw", response.headers["set-cookie"])

        # perform curl request
        cookie_header = {"Cookie": response.headers["set-cookie"]}
        response = self.make_curl_client_request("curl", headers=cookie_header)
        self.assertEqual(response.status, http.HTTPStatus.OK)

        # check Total pinned sessions in servers statistics
        nginx_8000 = ServerStats(tempesta, "default", cfg.get("Server", "ip"), 8000)
        nginx_8001 = ServerStats(tempesta, "default", cfg.get("Server", "ip"), 8001)
        self.assertEqual(nginx_8000.total_pinned_sessions, 0)
        self.assertEqual(nginx_8001.total_pinned_sessions, 1)

        # launch h2load
        client.options[0] += ' --header ":authority: app.com"'
        client.start()

        # 2
        # config Tempesta change,
        # reload, and check after reload
        self.reload_tfw_config(
            SRV_GRP_START,
            SRV_GRP_AFTER_RELOAD,
        )

        # 3
        # perform curl request
        response = self.make_curl_client_request("curl", headers=cookie_header)
        self.assertEqual(response.status, http.HTTPStatus.OK)

        # h2load stop
        self.wait_while_busy(client)
        client.stop()


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
