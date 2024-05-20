"""
On the fly reconfiguration stress test for ratio dynamic scheduler.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from helpers.control import servers_get_stats
from t_reconf.reconf_stress import LiveReconfStressTestBase

SCHED_OPTS_START = "ratio dynamic"
SCHED_OPTS_AFTER_RELOAD = "ratio dynamic minimum"

NGINX_CONFIG = """
load_module /usr/lib/nginx/modules/ngx_http_echo_module.so;

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
            echo_sleep ${delay};
            echo_exec @default;
        }
        location @default {
            root ${server_resources};
        }

        location /nginx_status {
            stub_status on;
        }
    }
}
"""

TEMPESTA_CONFIG = """
listen 443 proto=h2;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
max_concurrent_streams 10000;

cache 0;
frang_limits {http_strict_host_checking false;}
sched ratio dynamic;

""" + "".join(
    "server ${server_ip}:800%s;\n" % step for step in range(10)
)


class TestSchedRatioDynamicLiveReconf(LiveReconfStressTestBase):
    """This class tests on-the-fly reconfig of Tempesta for the ratio dynamic scheduler."""

    delays = [str(x / 10) for x in range(1, 11)]

    # 10 backend servers, each has unique delay before send response.
    backends = [
        {
            "id": f"nginx_800{step}",
            "type": "nginx",
            "port": f"800{step}",
            "delay": delay,
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        }
        for step, delay in enumerate(delays)
    ]

    tempesta = {
        "config": TEMPESTA_CONFIG,
    }

    min_server_weight = 30

    def test_reconf_on_the_fly_for_dynamic_ratio_sched(self) -> None:
        # launch all services except clients
        self.start_all_services(client=False)

        # check Tempesta config (before reload)
        self._check_start_tfw_config(
            SCHED_OPTS_START,
            SCHED_OPTS_AFTER_RELOAD,
        )

        # launch h2load
        client = self.get_client("h2load")
        client.start()
        self.wait_while_busy(client)

        self.check_servers_weights()

        # config Tempesta change,
        # reload, and check after reload
        self.reload_tfw_config(
            SCHED_OPTS_START,
            SCHED_OPTS_AFTER_RELOAD,
        )

        # stop h2load
        client.stop()

        # launch h2load after Tempesta reload
        client.start()
        self.wait_while_busy(client)
        client.stop()

        self.check_servers_weights()

    def check_servers_weights(self) -> None:
        tempesta = self.get_tempesta()
        servers = self.get_servers()
        tempesta.get_stats()
        servers_get_stats(servers)

        total_weight = len(servers) * 50
        weights = [
            (srv.get_name(), 1.0 * srv.requests / tempesta.stats.cl_msg_forwarded * total_weight)
            for srv in servers
        ]
        weights.sort()

        prev_name, prev_weight = weights[0]
        for name, weight in weights:
            self.assertLessEqual(
                weight,
                prev_weight,
                "Faster server %s got less weight than slower %s" % (prev_name, name)
                + f"Servers weights: {weights}",
            )
            if weight <= self.min_server_weight:
                break
            prev_weight = weight
            prev_name = name


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
