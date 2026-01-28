"""
Stress failovering testing.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import copy
import sys

from helpers import dmesg
from helpers.tf_cfg import cfg
from run_config import CONCURRENT_CONNECTIONS, DURATION, REQUESTS_COUNT, THREADS
from test_suite import marks, tester

SERVER_IP = cfg.get("Server", "ip")
TEMPESTA_WORKDIR = cfg.get("Tempesta", "workdir")

NGINX_CONFIG = """
pid ${pid};
worker_processes  auto;

events {
    worker_connections   1024;
    use epoll;
}

http {
    keepalive_timeout ${server_keepalive_timeout};
    keepalive_requests %s;
    sendfile         on;
    tcp_nopush       on;
    tcp_nodelay      on;

    open_file_cache max=1000;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors off;

    error_log /dev/null emerg;
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

TFW_CONFIF_WITH_DEFAULT_SCHED = f"""
    listen 443 proto=h2;

    tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
    tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
    tls_match_any_server_name;
    max_concurrent_streams 10000;
    frang_limits {{http_strict_host_checking false;}}

    cache 0;
    server {SERVER_IP}:8000;

    sched ratio;
"""

TFW_CONFIF_WITH_HASH_SCHED = f"""
    listen 443 proto=h2;

    tls_certificate {TEMPESTA_WORKDIR}/tempesta.crt;
    tls_certificate_key {TEMPESTA_WORKDIR}/tempesta.key;
    tls_match_any_server_name;
    max_concurrent_streams 10000;
    frang_limits {{http_strict_host_checking false;}}

    cache 0;
    server {SERVER_IP}:8000;

    sched hash;
"""


class FailoveringStressTestBase(tester.TempestaTest, base=True):
    """Base stress test class with default keep-alive requests
    configuration on HTTP server..
    """

    ka_requests = 100

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

    backends_template = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
    ]

    def setUp(self):
        self.backends = copy.deepcopy(self.backends_template)
        for backend in self.backends:
            backend["config"] = backend["config"] % self.ka_requests
        super().setUp()

    def run_test(self) -> None:
        # launch all services except clients
        self.start_all_services(client=False)

        # launch H2Load
        client = self.get_client("h2load")
        client.start()
        self.wait_while_busy(client)
        client.stop()
        self.assertNotIn(" 0 2xx, ", client.response_msg)


class TestStressFailovering(FailoveringStressTestBase):
    """Use ratio (default) and hash scheduler with small keep-alive requests
    configuration on HTTP server.

    Since overall amount of connections are small, failovering procedure
    will be loaded a lot.
    """

    ka_requests = 10

    def _set_tempesta_config_with_sched_ratio(self):
        self.get_tempesta().config.set_defconfig(TFW_CONFIF_WITH_DEFAULT_SCHED)

    def _set_tempesta_config_with_sched_hash(self):
        self.get_tempesta().config.set_defconfig(TFW_CONFIF_WITH_HASH_SCHED)

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="sched_ratio",
                tfw_config=_set_tempesta_config_with_sched_ratio,
            ),
            marks.Param(
                name="sched_hash",
                tfw_config=_set_tempesta_config_with_sched_hash,
            ),
        ]
    )
    @dmesg.limited_rate_on_tempesta_node
    def test_failovering(self, name, tfw_config) -> None:
        """Small amount of keep-alive requests, make Tempesta failover
        connections on a high rates.
        """
        tfw_config(self)
        self.run_test()

        tempesta = self.get_tempesta()
        tempesta.get_stats()

        self.assertNotEqual(
            tempesta.stats.cl_msg_received,
            tempesta.stats.cl_msg_forwarded,
        )
        self.assertTrue(tempesta.stats.cl_msg_other_errors > 0)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
