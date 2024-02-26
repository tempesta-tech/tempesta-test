"""
Stress failovering testing.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import sys

from framework import tester
from run_config import CONCURRENT_CONNECTIONS, DURATION, REQUESTS_COUNT, THREADS

NGINX_CONFIG = """
pid ${pid};
worker_processes  auto;

events {
    worker_connections   20;
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


class TestStressRatioFailovering(tester.TempestaTest):
    """Use ratio (default) scheduler with small keep-alive requests
    configuration on HTTP server.

    Since overall amount of connections are small, failovering procedure
    will be loaded a lot.
    """

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

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG % 10,
        },
    ]

    tempesta = {
        "config": """
            listen ${tempesta_ip}:443 proto=h2;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;

            cache 0;
            server ${server_ip}:8000;

            sched ratio;
        """,
    }

    def run_test(self) -> None:
        # launch all services except clients
        self.start_all_services(client=False)

        # launch H2Load
        client = self.get_client("h2load")
        client.start()
        self.wait_while_busy(client)
        client.stop()
        self.assertNotIn(" 0 2xx, ", client.response_msg)

    def test_failovering(self) -> None:
        """Small amount of keep-alive requests, make Tempesta failover
        connections on a high rates.
        """
        self.run_test()

        tempesta = self.get_tempesta()
        tempesta.get_stats()

        self.assertNotEqual(
            tempesta.stats.cl_msg_received,
            tempesta.stats.cl_msg_forwarded,
        )
        self.assertTrue(tempesta.stats.cl_msg_other_errors > 0)


class TestStressUnlimKeepAliveReq(TestStressRatioFailovering):

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG % sys.maxsize,  # 2**63 - 1
        },
    ]

    def test_failovering(self) -> None:
        """Almost unlimited maximum amount of requests during one connection.
        No connections failovering in this case.
        """
        self.run_test()

        tempesta = self.get_tempesta()
        tempesta.get_stats()

        self.assertEqual(
            tempesta.stats.cl_msg_received,
            tempesta.stats.cl_msg_forwarded,
        )
        self.assertEqual(tempesta.stats.cl_msg_other_errors, 0)


class TestStressHashFailovering(TestStressRatioFailovering):
    """Absolutely the same as TestStressRatioFailovering,
    bus uses `hash` scheduler instead.
    """

    tempesta = {
        "config": """
            listen ${tempesta_ip}:443 proto=h2;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;

            cache 0;
            server ${server_ip}:8000;

            sched hash;
        """,
    }


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
