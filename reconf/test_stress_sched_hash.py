"""
On the fly reconfiguration stress test for hash scheduler.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from helpers.control import Tempesta
from reconf.reconf_stress_base import LiveReconfStressTestCase

SCHED_OPTS_START = "hash"
SCHED_OPTS_AFTER_RELOAD = "ratio dynamic"

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

TEMPESTA_CONFIG = """
listen ${tempesta_ip}:443 proto=h2;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;

cache 0;

sched hash;

""" + "".join(
    "server ${server_ip}:800%s;\n" % step for step in range(10)
)


class TestSchedHashLiveReconf(LiveReconfStressTestCase):
    """
    This class tests on-the-fly reconfig of Tempesta for the hash scheduler.
    This test covers the case of changing the scheduler attached to a server group.
    """

    backends_count = 10
    deviation = 0.2
    msg = "Only one server should got most of the load"

    tempesta = {"config": TEMPESTA_CONFIG}

    backends = [
        {
            "id": f"nginx_{step}",
            "type": "nginx",
            "port": f"80{step}" if step > 9 else f"800{step}",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        }
        for step in range(backends_count)
    ]

    def test_reconf_on_the_fly_for_hash_sched(self):
        """Test of changing the scheduler attached to a server group."""
        # launch all services and getting Tempesta instance
        self.start_all_services()
        tempesta = self.get_tempesta()

        # check Tempesta config (before reload)
        self._check_start_tfw_config(SCHED_OPTS_START, SCHED_OPTS_AFTER_RELOAD)

        # launch H2Load
        client = self.get_client("h2load")
        self.wait_while_busy(client)
        client.stop()

        self.assertEqual(client.returncode, 0)
        self.assertNotIn(" 0 2xx, ", client.response_msg)

        self.assertAlmostEqual(
            self._get_load_distribution_btw_srvs(tempesta),
            tempesta.stats.cl_msg_received,
            delta=(tempesta.stats.cl_msg_received * self.deviation),
            msg=self.msg,
        )

        # config Tempesta change,
        # reload Tempesta, check logs,
        # and check config Tempesta after reload
        self.reload_tfw_config(
            SCHED_OPTS_START,
            SCHED_OPTS_AFTER_RELOAD,
        )

        # launch h2load after Tempesta reload
        client.start()
        self.wait_while_busy(client)
        client.stop()

        self.assertEqual(client.returncode, 0)
        self.assertNotIn(" 0 2xx, ", client.response_msg)

        self.assertNotAlmostEqual(
            self._get_load_distribution_btw_srvs(tempesta),
            tempesta.stats.cl_msg_received,
            delta=(tempesta.stats.cl_msg_received * self.deviation),
            msg=self.msg,
        )

    def _get_load_distribution_btw_srvs(self, tempesta: Tempesta) -> int:
        """For hash scheduler, only one server must pull mostly all the load.

        Other servers may also receive some requests while primary connection is not live.

        Args:
            tempesta: Object of working Tempesta.

        Returns:
            Number of requests received by the server.
        """
        tempesta.get_stats()

        for server in self.get_servers():
            server.get_stats()

        loaded_servers = []
        for srv in self.get_servers():
            if srv.requests:
                loaded_servers.append(srv.requests)
        loaded_servers.sort(reverse=True)

        self.assertTrue(loaded_servers)

        return loaded_servers[0]


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
