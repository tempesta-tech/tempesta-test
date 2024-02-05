"""
On the fly reconfiguration stress test for health monitor.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from typing import List

from framework.external_client import ExternalTester
from helpers.control import Tempesta
from helpers.tempesta import ServerStats
from helpers.tf_cfg import cfg
from reconf.reconf_stress_base import LiveReconfStressTestCase
from run_config import CONCURRENT_CONNECTIONS, DURATION, REQUESTS_COUNT, THREADS

HEALTH_MONITOR_START = "health h_monitor1;"
HEALTH_MONITOR_AFTER_RELOAD = "health h_monitor2;"

TEMPESTA_CONFIG = """
listen ${tempesta_ip}:443 proto=h2;

server_failover_http 404 50 5;
server_failover_http 502 50 5;
server_failover_http 403 50 5;

health_check h_monitor1 {
    request		"GET / HTTP/1.1\r\n\r\n";
    request_url	"/";
    resp_code	200;
    timeout		1;
}

health_check h_monitor2 {
    request		"GET / HTTP/1.1\r\n\r\n";
    request_url	"/monitor/";
    resp_code	200;
    resp_crc32	auto;
    timeout		3;
}

srv_group main {
    server ${server_ip}:8000;
    server ${server_ip}:8001;

    health h_monitor1;
}

vhost main{
    proxy_pass main;
}

tls_match_any_server_name;
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;

http_chain {
    -> main;
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
    keepalive_requests ${server_keepalive_requests};
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

        location /monitor/ {
            return 200;
        }

        location /nginx_status {
            stub_status on;
        }
    }
}
"""


class TestHealthMonitorLiveReconf(LiveReconfStressTestCase):
    """This class stress tests on-the-fly reconfig of Tempesta for the health monitor."""

    backends = [
        {
            "id": f"nginx{step}",
            "type": "nginx",
            "port": f"800{step}",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        }
        for step in range(2)
    ]

    clients = [
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

    tempesta = {"config": TEMPESTA_CONFIG}

    def test_reconf_on_the_fly_for_health_monitor(self):
        # launch all services except clients and getting Tempesta instance
        self.start_all_services(client=False)
        tempesta: Tempesta = self.get_tempesta()

        # start config Tempesta check (before reload)
        self._check_start_config(
            tempesta,
            HEALTH_MONITOR_START,
            HEALTH_MONITOR_AFTER_RELOAD,
        )

        # launch H2Load client - HTTP/2 benchmarking tool
        client: ExternalTester = self.get_client("h2load")
        client.start()

        stats_srvs: List[ServerStats] = [
            ServerStats(tempesta, "main", cfg.get("Server", "ip"), port) for port in (8000, 8001)
        ]

        self.check_servers_stats(stats_srvs)

        # config Tempesta change,
        # reload Tempesta, check logs,
        # and check config Tempesta after reload
        self.reload_config(
            tempesta,
            HEALTH_MONITOR_START,
            HEALTH_MONITOR_AFTER_RELOAD,
        )

        self.check_servers_stats(stats_srvs, timeout=3)

        # H2Load stop
        self.wait_while_busy(client)
        client.stop()

        self.assertEqual(client.returncode, 0)
        self.assertNotIn(" 0 2xx, ", client.response_msg)

    def check_servers_stats(
        self,
        stats_srvs: List[ServerStats],
        timeout: int = 1,
    ) -> None:
        """
        Checking the servers statistics.

        Args:
            stats_srvs: list of ServerStats objects
        Kwargs:
            timeout: integer object is the time in seconds until the next
                monitoring request is sent to the server. Defaults to 1.

        """
        for srv in stats_srvs:
            self.assertTrue(srv.server_health)
            self.assertTrue(srv.is_enable_health_monitor)
            self.assertEqual(srv.health_request_timeout, timeout)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
