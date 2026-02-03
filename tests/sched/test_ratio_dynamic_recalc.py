"""
Test for ratio dynamic scheduler. Check automatic weight re-calculation
when backend performance is changed.
Difference from test_ratio_dynamic.py: server latency changes in time,
so  it should get higher or lower weight.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework.services.wrk_client import Wrk
from framework.test_suite import tester
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

"""


class RatioDynamic(tester.TempestaTest):
    """Check that server weight is re-calculated based on it's performance."""

    base_delay = "0.15"
    low_delay = "0"
    high_delay = "0.3"

    backends = [
        # Server with constant delay
        {
            "id": "nginx_constant",
            "type": "nginx",
            "port": "8000",
            "delay": base_delay,
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        # Delay of the server is changing, thus 3 different config files
        # describe one server
        {
            "id": "nginx_dynamic",
            "type": "nginx",
            "port": "8001",
            "delay": base_delay,
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_dynamic_slow",
            "type": "nginx",
            "port": "8001",
            "delay": high_delay,
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        },
        {
            "id": "nginx_dynamic_fast",
            "type": "nginx",
            "port": "8001",
            "delay": low_delay,
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

    # Both servers concurrent for the same resources, so some unfair in load
    # balancing is possible
    initial_fairness = 0.2

    min_duration = max(DURATION, 30)

    def run_test(self, srv_const, srv_dyn, new_server_name=None):
        """Run wrk and get performance statistics from backends and Tempesta.
        If 'new_server_name' of 'srv_dyn' is set, first reload its
        configuration.
        """
        if new_server_name:
            srv_dyn.stop()
            srv_dyn = self.get_server(new_server_name)
            srv_dyn.start()

        client = self.get_client("client")
        if isinstance(client, Wrk):
            client.duration = self.min_duration
        else:
            client.options[0] += f" --duration {self.min_duration}"

        client.start()
        self.wait_while_busy(client)
        client.stop()

        return (srv_const, srv_dyn)

    def calc_weight(self, servers, perfstat):
        """Calculate weights of servers during last wrk run"""
        srv_const, srv_dyn = servers
        tempesta = self.get_tempesta()

        tempesta.get_stats()
        srv_const.get_stats()
        srv_dyn.get_stats()

        cl_reqs = perfstat["client_requests"] = (
            tempesta.stats.cl_msg_forwarded - perfstat["tot_client_requests"]
        )
        perfstat["tot_client_requests"] = tempesta.stats.cl_msg_forwarded

        c_reqs = perfstat["const_server_requests"] = (
            srv_const.requests - perfstat["tot_const_server_requests"]
        )
        perfstat["tot_const_server_requests"] = srv_const.requests
        # Dynamic server is restarted before each test, it has always clean
        # statistics
        d_reqs = perfstat["dyn_server_requests"] = srv_dyn.requests

        tot_weight = 100  # Weight normalisation for 2 servers in group
        w_const = 1.0 * tot_weight * c_reqs / cl_reqs
        w_dyn = 1.0 * tot_weight * d_reqs / cl_reqs

        return w_const, w_dyn

    def test_load_distribution(self):
        """Configure slow and fast servers. The faster server is the more
        weight it should get.
        """
        srv_const = self.get_server("nginx_constant")
        srv_dyn = self.get_server("nginx_dynamic")
        srv_const.start()
        srv_dyn.start()
        self.start_tempesta()

        perfstat = {
            "client_requests": 0,
            "tot_client_requests": 0,
            "const_server_requests": 0,
            "tot_const_server_requests": 0,
            "dyn_server_requests": 0,
        }

        servers = self.run_test(srv_const, srv_dyn)
        self.calc_weight(servers, perfstat)

        _, srv_dyn = servers
        servers = self.run_test(srv_const, srv_dyn, "nginx_dynamic_slow")
        w_const, w_dyn = self.calc_weight(servers, perfstat)
        self.assertGreater(
            w_const, w_dyn, msg=("Slower server got higher weight. " "%d vs %d" % (w_const, w_dyn))
        )

        _, srv_dyn = servers
        servers = self.run_test(srv_const, srv_dyn, "nginx_dynamic_fast")
        w_const, w_dyn = self.calc_weight(servers, perfstat)
        self.assertLess(
            w_const, w_dyn, msg=("Slower server got higher weight. " "%d vs %d" % (w_const, w_dyn))
        )


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

    When a server performance is changing in time, ratio predict performs
    dynamic weight recalculations. Same as 'ratio dynamic', but 'predict'
    scheduler smooths load spikes better.
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
