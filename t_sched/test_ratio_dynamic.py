"""
Test for ratio dynamic scheduler. Check automatic weight calculation
for servers that have different (mostly constant) latency.
Difference from test_ratio_static.py: weights of servers are estimated
dynamically.

The faster the server is the more load it should get. Use echo_nginx_module
to add programmable delay before response is sent. Every next server has a
bigger delay, so resulting weights of servers should have the reverse order.

In heavy concurrent environment, where all servers are started on the
same hardware (which is always true in our tests), some servers may get
unpredictable delays. Such delays may significantly affect dynamic load
distribution. After a lot of testing it turned out that:
- a few slowest  server are more likely to be affected by the issue;
- unlucky fast server may not get enough of cpu time to keep expected latency,
and has no chances to get more cpu time, since it doesn't get enough job
(requests).
To fight with this tricky situation, ignore servers which got weight less than
30, when compare resulting weights. All servers can't have weight lower than
30 in the same time, so at least some checks are performed.

In dynamic or predict mode load balancing between servers is only predictable,
if they have the same number of connections. This behaviour is different
from the ratio static mode.

"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester
from framework.wrk_client import Wrk
from helpers import tf_cfg
from helpers.control import servers_get_stats
from run_config import DURATION

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

    # [ debug | info | notice | warn | error | crit | alert | emerg ]
    # Fully disable log errors.
    error_log /dev/null emerg;

    # Disable access log altogether.
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
listen 80;
listen 443 proto=h2;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;

cache 0;

sched ${sched_opts};
server ${server_ip}:8000;
server ${server_ip}:8001;
server ${server_ip}:8002;
server ${server_ip}:8003;
server ${server_ip}:8004;
server ${server_ip}:8005;
server ${server_ip}:8006;
server ${server_ip}:8007;
server ${server_ip}:8008;
server ${server_ip}:8009;

"""


class RatioDynamic(tester.TempestaTest):
    """Use 'ratio dynamic' scheduler. The faster server is the
    more load it get.
    """

    # 10 backend servers, each has unique delay before send response.
    backends = [
        {
            "id": "nginx_8000",
            "type": "nginx",
            "port": "8000",
            "delay": "0.1",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8001",
            "type": "nginx",
            "port": "8001",
            "delay": "0.2",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8002",
            "type": "nginx",
            "port": "8002",
            "delay": "0.3",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8003",
            "type": "nginx",
            "port": "8003",
            "delay": "0.4",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8004",
            "type": "nginx",
            "port": "8004",
            "delay": "0.5",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8005",
            "type": "nginx",
            "port": "8005",
            "delay": "0.6",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8006",
            "type": "nginx",
            "port": "8006",
            "delay": "0.7",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8007",
            "type": "nginx",
            "port": "8007",
            "delay": "0.8",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8008",
            "type": "nginx",
            "port": "8008",
            "delay": "0.9",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_8009",
            "type": "nginx",
            "port": "8009",
            "delay": "1",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
    ]

    clients = [
        {
            "id": "client",
            "type": "wrk",
            "addr": "${tempesta_ip}:80",
        },
    ]

    tempesta = {
        "sched_opts": "ratio dynamic",
        "config": TEMPESTA_CONFIG,
    }

    min_server_weight = 30
    min_duration = max(DURATION, 30)

    def test_load_distribution(self):
        """Configure slow and fast servers. The faster server, the more
        weight it should get.
        """
        client = self.get_client("client")

        if isinstance(client, Wrk):
            client.duration = self.min_duration
        else:
            client.options[0] += f" --duration {self.min_duration}"

        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()

        self.wait_while_busy(client)
        client.stop()

        tempesta = self.get_tempesta()
        servers = self.get_servers()
        tempesta.get_stats()
        servers_get_stats(servers)

        cl_reqs = tempesta.stats.cl_msg_forwarded
        tot_weight = len(servers) * 50  # for weight normalisation.
        weights = [(srv.get_name(), 1.0 * srv.requests / cl_reqs * tot_weight) for srv in servers]
        weights.sort()
        tf_cfg.dbg(3, "Calculated server weights: %s" % weights)

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


class RatioDynamicMin(RatioDynamic):
    tempesta = {"sched_opts": "ratio dynamic minimum", "config": TEMPESTA_CONFIG}


class RatioDynamicMax(RatioDynamic):
    tempesta = {"sched_opts": "ratio dynamic maximum", "config": TEMPESTA_CONFIG}


class RatioDynamicAv(RatioDynamic):
    tempesta = {"sched_opts": "ratio dynamic average", "config": TEMPESTA_CONFIG}


class RatioDynamicPerc(RatioDynamic):
    tempesta = {"sched_opts": "ratio dynamic percentile", "config": TEMPESTA_CONFIG}


class RatioPredict(RatioDynamic):
    """Use 'ratio predict' scheduler.

    When a server performance is pretty constant in time, ratio predict performs
    close to ratio dynamic. But predict scheduler better smooths load spikes.
    """

    # Prediction timeouts are 30/15 by default. Enforce minimum test duration
    # to bigger value to use predicts.
    min_duration = max(DURATION, 60)

    tempesta = {"sched_opts": "ratio predict", "config": TEMPESTA_CONFIG}


class RatioPredictMin(RatioPredict):
    tempesta = {"sched_opts": "ratio predict minimum", "config": TEMPESTA_CONFIG}


class RatioPredictMax(RatioPredict):
    tempesta = {"sched_opts": "ratio predict maximum", "config": TEMPESTA_CONFIG}


class RatioPredictAv(RatioPredict):
    tempesta = {"sched_opts": "ratio predict average", "config": TEMPESTA_CONFIG}


class RatioPredictPerc(RatioPredict):
    tempesta = {"sched_opts": "ratio predict percentile", "config": TEMPESTA_CONFIG}
