"""
Pipeline stress testing.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework.wrk_client import Wrk
from helpers import dmesg, tf_cfg
from test_suite import tester

PIPELINE_LUA = r"""-- example script demonstrating HTTP pipelining

local_init = function(args)
   local r = {}
   r[1] = wrk.format("GET", "/")
   r[2] = wrk.format("GET", "/")
   r[3] = wrk.format("GET", "/")
   r[4] = wrk.format("GET", "/")
   r[5] = wrk.format("GET", "/")
   r[6] = wrk.format("GET", "/")
   r[7] = wrk.format("GET", "/")

   req = table.concat(r)
end

request = function()
   return req
end
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


class TestStressPipeline(tester.TempestaTest):
    """Stress test with pipelined requests."""

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG,
        }
    ]

    clients = [
        {
            "id": "wrk",
            "type": "wrk",
            "addr": "${tempesta_ip}:80",
        },
    ]

    tempesta = {
        "config": """
            cache 0;
            server ${server_ip}:8000;
            frang_limits {http_strict_host_checking false;}
        """,
    }

    pipelined_req = 7
    errors_500 = 0
    errors_502 = 0
    errors_504 = 0
    errors_connect = 0
    errors_read = 0
    errors_write = 0
    errors_timeout = 0

    def routine(self, lua: str) -> Wrk:
        wrk = self.get_client("wrk")
        wrk.set_script("wrk", lua)

        self.start_all_services(client=False)

        wrk.start()
        self.wait_while_busy(wrk)
        wrk.stop()
        return wrk

    def show_performance(self) -> None:
        client = self.get_client("wrk")

        if tf_cfg.v_level() < 2:
            return
        req_total = err_total = rate_total = 0
        req, err, rate, _ = client.results()
        req_total += req
        err_total += err
        rate_total += rate

    def assert_client(self, req, err, statuses) -> None:
        msg = "HTTP client detected %i/%i errors. Results: %s" % (err, req, str(statuses))
        e_500 = statuses.get(500, 0)
        e_502 = statuses.get(502, 0)
        e_504 = statuses.get(504, 0)
        e_connect = 0
        e_read = 0
        e_write = 0
        e_timeout = 0

        # "named" statuses are wrk-dependent results
        if "connect_error" in statuses.keys():
            e_connect = statuses["connect_error"]
        if "read_error" in statuses.keys():
            e_read = statuses["read_error"]
        if "write_error" in statuses.keys():
            e_write = statuses["write_error"]
        if "timeout_error" in statuses.keys():
            e_timeout = statuses["timeout_error"]
        if 500 in statuses.keys():
            e_500 = statuses[500]
        if 502 in statuses.keys():
            e_502 = statuses[502]
        if 504 in statuses.keys():
            e_504 = statuses[504]

        self.errors_connect += e_connect
        self.errors_read += e_read
        self.errors_write += e_write
        self.errors_timeout += e_timeout
        self.errors_500 += e_500
        self.errors_502 += e_502
        self.errors_504 += e_504
        self.assertGreater(req, 0, msg="No work was done by the client")
        self.assertEqual(err, e_500 + e_502 + e_504 + e_connect, msg=msg)

    def assert_clients(self) -> None:
        """Check benchmark result: no errors happen, no packet loss."""
        client = self.get_client("wrk")
        tempesta = self.get_tempesta()
        tempesta.get_stats()

        cl_req_cnt = 0
        cl_conn_cnt = 0
        self.errors_502 = 0
        self.errors_504 = 0
        self.errors_connect = 0
        self.errors_read = 0
        self.errors_write = 0
        self.errors_timeout = 0

        req, err, _, statuses = client.results()
        cl_req_cnt += req
        cl_conn_cnt += client.connections * self.pipelined_req
        self.assert_client(req, err, statuses)

        exp_min = cl_req_cnt
        exp_max = cl_req_cnt + cl_conn_cnt

        self.assertTrue(
            tempesta.stats.cl_msg_received >= exp_min and tempesta.stats.cl_msg_received <= exp_max,
            msg="Tempesta received bad number %d of messages, expected [%d:%d]"
            % (tempesta.stats.cl_msg_received, exp_min, exp_max),
        )

    def assert_tempesta(self) -> None:
        """Don't make asserts by default"""
        client = self.get_client("wrk")
        tempesta = self.get_tempesta()
        tempesta.get_stats()

        cl_conn_cnt = 0
        cl_conn_cnt += client.connections

    def generic_asserts_test(self) -> None:
        self.show_performance()
        self.assert_clients()
        self.assert_tempesta()

    @dmesg.limited_rate_on_tempesta_node
    def test_pipeline(self) -> None:
        self.routine(PIPELINE_LUA)
        self.generic_asserts_test()


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
