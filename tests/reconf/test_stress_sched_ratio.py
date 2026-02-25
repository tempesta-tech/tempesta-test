"""
On the fly reconfiguration stress test for ratio scheduler.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from tests.reconf.reconf_stress import LiveReconfStressTestBase

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

frang_limits {http_strict_host_checking false;}
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
max_concurrent_streams 10000;

cache 0;
server ${server_ip}:8000;
server ${server_ip}:8001;

sched ratio static;
"""


class TestSchedRatioLiveReconf(LiveReconfStressTestBase):
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

    tempesta = {
        "config": TEMPESTA_CONFIG,
    }

    # Base precision (10% if server weight is [30, 100])
    precision = 0.1
    # Minimum request count delta used for short term tests.
    min_delta = 10

    dbg_msg = "Server {0} received {1} requests, but [{2}, {3}] was expected"

    async def test_reconf_on_the_fly_for_static_ratio_sched(self) -> None:
        # launch all services except clients
        await self.start_all_services(client=False)

        # getting servers instances
        servers = self.get_servers()

        # check Tempesta config (before reload)
        self._check_start_tfw_config(SRV_WEIGHT_START, SRV_WEIGHT_AFTER_RELOAD)

        # launch h2load
        client = self.get_client("h2load")
        client.start()
        await self.wait_while_busy(client)

        # get statistics on expected requests
        s_reqs_expected: float = self.get_n_expected_reqs(servers)
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
        # reload, and check after reload
        self.reload_tfw_config(
            SRV_WEIGHT_START,
            SRV_WEIGHT_AFTER_RELOAD,
        )

        # h2load stop
        client.stop()

        # launch h2load after Tempesta reload
        client.start()
        await self.wait_while_busy(client)

        # get statistics on expected requests
        s_reqs_expected: float = self.get_n_expected_reqs(servers)
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

    def get_n_expected_reqs(self, servers) -> float:
        tempesta = self.get_tempesta()
        tempesta.get_stats()
        for srv in servers:
            srv.get_stats()
        return tempesta.stats.cl_msg_forwarded / len(servers)
