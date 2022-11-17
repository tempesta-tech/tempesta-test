"""
Test for ratio dynamic scheduler. Check automatic weight re-calculation
when backend performance is changed.
Difference from test_ratio_dynamic.py: server latency changes in time,
so  it should get higher or lower weight.
"""

import unittest

import helpers.tf_cfg as tf_cfg
from framework import tester
from helpers.control import servers_get_stats

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018 Tempesta Technologies, Inc."
__license__ = "GPL2"

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
            "id": "wrk",
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

    min_duration = 30

    def run_test(self, srv_const, srv_dyn, new_server_name=None):
        """Run wrk and get performance statistics from backends and Tempesta.
        If 'new_server_name' of 'srv_dyn' is set, first reload its
        configuration.
        """
        if new_server_name:
            srv_dyn.stop()
            srv_dyn = self.get_server(new_server_name)
            srv_dyn.start()

        wrk = self.get_client("wrk")
        self.start_all_clients()
        self.wait_while_busy(wrk)
        wrk.stop()

        return (srv_const, srv_dyn)

    def calc_weight(self, servers, perfstat):
        """Calculate weights of servers during last wrk run"""
        srv_const, srv_dyn = servers
        tempesta = self.get_tempesta()

        tempesta.get_stats()
        servers_get_stats([srv_const, srv_dyn])

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

        tf_cfg.dbg(
            3,
            "Total reqs %d; const_srv: reqs %d weight %d; "
            "dyn_srv reqs %d weight %d " % (cl_reqs, c_reqs, w_const, d_reqs, w_dyn),
        )

        return w_const, w_dyn

    def test_load_distribution(self):
        """Configure slow and fast servers. The faster server is the more
        weight it should get.
        """
        duration = int(tf_cfg.cfg.get("General", "Duration"))
        if duration < self.min_duration:
            raise unittest.TestCase.skipTest(self, "Test is not stable on short periods")
        if tf_cfg.cfg.get("Tempesta", "hostname") == tf_cfg.cfg.get("Server", "hostname"):
            raise unittest.TestCase.skipTest(
                self, "Test is not stable if Tempesta and Servers " "are started on the same node."
            )

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

        tf_cfg.dbg(3, "Servers has same latency, expect almost equal weights")
        servers = self.run_test(srv_const, srv_dyn)
        self.calc_weight(servers, perfstat)

        tf_cfg.dbg(3, "Slow down one server, expect its weight to decrease")
        _, srv_dyn = servers
        servers = self.run_test(srv_const, srv_dyn, "nginx_dynamic_slow")
        w_const, w_dyn = self.calc_weight(servers, perfstat)
        self.assertGreater(
            w_const, w_dyn, msg=("Slower server got higher weight. " "%d vs %d" % (w_const, w_dyn))
        )

        tf_cfg.dbg(3, "Speed up one server, expect its weight to increase")
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
    min_duration = 60

    tempesta = {"sched_opts": "ratio predict", "config": TEMPESTA_CONFIG}


class RatioPredictMin(RatioPredict):

    tempesta = {"sched_opts": "ratio predict minimum", "config": TEMPESTA_CONFIG}


class RatioPredictMax(RatioPredict):

    tempesta = {"sched_opts": "ratio predict maximum", "config": TEMPESTA_CONFIG}


class RatioPredictAv(RatioPredict):

    tempesta = {"sched_opts": "ratio predict average", "config": TEMPESTA_CONFIG}


class RatioPredictPerc(RatioPredict):

    tempesta = {"sched_opts": "ratio predict percentile", "config": TEMPESTA_CONFIG}
