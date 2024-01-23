"""
On the fly reconfiguration stress test for ratio scheduler.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework.external_client import ExternalTester
from helpers.control import Tempesta, servers_get_stats
from reconf.reconf_stress_base import LiveReconfStressTestCase
from run_config import CONCURRENT_CONNECTIONS, DURATION, REQUESTS_COUNT, THREADS

SRV_WEIGHT_START = ":8001;"
SRV_WEIGHT_AFTER_RELOAD = ":8001 weight=90;"

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
            root ${server_resources};
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
server ${server_ip}:8000;
server ${server_ip}:8001;

sched ratio static;
"""


class TestSchedRatioLiveReconf(LiveReconfStressTestCase):
    """
    This class tests on-the-fly reconfig of Tempesta for the ratio scheduler.
    Use 'ratio static' scheduler with default weights. Load must be
    distributed equally across all servers.
    """

    backends = [
        {
            "id": f"nginx_800{count}",
            "type": "nginx",
            "port": f"800{count}",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        }
        for count in range(2)
    ]

    clients = [
        {
            "id": "h2load",
            "type": "external",
            "binary": "h2load",
            "ssl": True,
            "cmd_args": (
                " https://${tempesta_ip}/443/"
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

    # Base precision (10% if server weight is [30, 100])
    precision = 0.1
    # Minimum request count delta used for short term tests.
    min_delta = 10

    dbg_msg = "Server {0} received {1} requests, but [{2}, {3}] was expected"

    def test_reconf_on_the_fly_for_static_ratio_sched(self) -> None:
        # launch all services except clients
        self.start_all_services(client=False)
        # getting Tempesta and servers instances
        tempesta: Tempesta = self.get_tempesta()
        servers = self.get_servers()

        # check Tempesta config (before reload)
        self._check_start_config(tempesta, SRV_WEIGHT_START, SRV_WEIGHT_AFTER_RELOAD)

        # launch h2load client - HTTP/2 benchmarking tool
        client: ExternalTester = self.get_client("h2load")
        client.start()
        self.wait_while_busy(client)

        # get statistics on expected requests
        s_reqs_expected: float = self.get_n_expected_reqs(tempesta, servers)
        delta: float = max(self.precision * s_reqs_expected, self.min_delta)

        for srv in servers:
            self.assertAlmostEqual(
                srv.requests,
                s_reqs_expected,
                delta=delta,
                msg=self.dbg_msg.format(
                    srv.get_name(),
                    srv.requests,
                    s_reqs_expected - delta,
                    s_reqs_expected + delta,
                ),
            )

        # config Tempesta change,
        # reload Tempesta, check logs,
        # and check config Tempesta after reload
        self.reload_config(
            tempesta,
            SRV_WEIGHT_START,
            SRV_WEIGHT_AFTER_RELOAD,
        )

        # h2load stop
        client.stop()
        self.assertEqual(client.returncode, 0)

        # launch h2load after Tempesta reload
        client.start()
        self.wait_while_busy(client)

        # get statistics on expected requests
        s_reqs_expected: float = self.get_n_expected_reqs(tempesta, servers)
        delta: float = max(self.precision * s_reqs_expected, self.min_delta)

        for srv in servers:
            self.assertNotAlmostEqual(
                srv.requests,
                s_reqs_expected,
                delta=delta,
                msg=self.dbg_msg.format(
                    srv.get_name(),
                    srv.requests,
                    s_reqs_expected - delta,
                    s_reqs_expected + delta,
                ),
            )

        # h2load stop
        client.stop()
        self.assertEqual(client.returncode, 0)

    def get_n_expected_reqs(self, tempesta: Tempesta, servers) -> float:
        tempesta.get_stats()
        servers_get_stats(servers)
        return tempesta.stats.cl_msg_forwarded / len(servers)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
