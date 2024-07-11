"""
Tests for health monitoring functionality.
"""

from __future__ import print_function

import time

from access_log.test_access_log_h2 import backends
from framework import templates, tester
from framework.parameterize import param, parameterize, parameterize_class
from helpers import dmesg, tempesta, tf_cfg, util

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

REQ_COUNT = 100

TEMPESTA_CONFIG = """

server_failover_http 404 50 5;
server_failover_http 502 50 5;
server_failover_http 403 50 5;
cache 0;

health_check h_monitor1 {
    request "GET / HTTP/1.1\r\n\r\n";
    request_url	"/";
    resp_code	200;
    resp_crc32	auto;
    timeout		1;
}


srv_group srv_grp1 {
        server ${server_ip}:8080;
        server ${server_ip}:8081;
        server ${server_ip}:8082;

        health h_monitor1;
}

vhost srv_grp1{
        proxy_pass srv_grp1;
}

http_chain {
-> srv_grp1;
}
%s
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

    # [ debug | info | notice | warn | error | crit | alert | emerg ]
    # Fully disable log errors.
    error_log /dev/null emerg;

    # Disable access log altogether.
    access_log off;

    server {
        listen        ${server_ip}:%s;

        location / {
            %s
        }
        location /nginx_status {
            stub_status on;
        }
    }
}
"""


class TestHealthMonitor(tester.TempestaTest):
    """Test for health monitor functionality with stress option.
    Testing process is divided into several stages:
    1. Run tempesta-fw without backends
    2. Create two backends for enabled HM server's state:
    403/404 responses will be returned until the configured time limit is
    reached.
    3. Create a backend, which returns valid for HM response 200 code and ensure
    that requested statuses are 404/403 until HM disables the old servers
    and responses become 502 for the old and 200 for the new backends
    4. Now 403/404 backends are marked unhealthy and must be gone
    """

    tempesta = {
        "config": TEMPESTA_CONFIG % "",
    }

    backends = [
        {
            "id": "nginx1",
            "type": "nginx",
            "port": "8080",
            "status_uri": "http://${server_ip}:8080/nginx_status",
            "config": NGINX_CONFIG
            % (
                8080,
                """

return 403;
""",
            ),
        },
        {
            "id": "nginx2",
            "type": "nginx",
            "port": "8081",
            "status_uri": "http://${server_ip}:8081/nginx_status",
            "config": NGINX_CONFIG
            % (
                8081,
                """

return 404;
""",
            ),
        },
        {
            "id": "nginx3",
            "type": "nginx",
            "port": "8082",
            "status_uri": "http://${server_ip}:8082/nginx_status",
            "config": NGINX_CONFIG
            % (
                8082,
                """

return 200;
""",
            ),
        },
    ]

    clients = [
        {
            "id": "curl",
            "type": "external",
            "binary": "curl",
            "cmd_args": (' -o /dev/null -s -w "%{http_code}\n" ' "http://${tempesta_ip}"),
        },
    ]

    def wait_for_server(self, srv):
        srv.start()
        while srv.state != "started":
            pass
        srv.wait_for_connections()

    def run_curl(self, n=1):
        res = []
        for _ in range(n):
            curl = self.get_client("curl")
            curl.run_start()
            curl.proc_results = curl.resq.get(True, 1)
            res.append(int((curl.proc_results[0].decode("utf-8"))[:-1]))
        return res

    def test(self):
        """Test health monitor functionality with described stages"""
        self.start_tempesta()

        # 1
        back1 = self.get_server("nginx1")
        back2 = self.get_server("nginx2")
        back3 = self.get_server("nginx3")
        res = self.run_curl(REQ_COUNT)
        self.assertTrue(list(set(res)) == [502], "No 502 in statuses")

        # 2
        self.wait_for_server(back1)
        self.wait_for_server(back2)
        res = self.run_curl(REQ_COUNT)
        self.assertTrue(sorted(list(set(res))) == [403, 404], "Not valid status")

        # 3
        self.wait_for_server(back3)
        res = self.run_curl(REQ_COUNT)
        self.assertTrue(sorted(list(set(res))) == [200, 403, 404], "Not valid status")

        # 4
        res = self.run_curl(REQ_COUNT)
        self.assertTrue(sorted(list(set(res))) == [200], "Not valid status")
        back3.stop()


DEPROXY_CLIENT = {
    "id": "deproxy",
    "type": "deproxy",
    "addr": "${tempesta_ip}",
    "port": "80",
}

DEPROXY_CLIENT_H2 = {
    "id": "deproxy",
    "type": "deproxy_h2",
    "addr": "${tempesta_ip}",
    "port": "443",
    "ssl": True,
}


@parameterize_class(
    [
        {"name": "Http", "clients": [DEPROXY_CLIENT]},
        {"name": "H2", "clients": [DEPROXY_CLIENT_H2]},
    ]
)
class TestHealthStat(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
        },
    ]

    def setUp(self):
        tempesta_config = """
            listen 80;
            listen 443 proto=h2;
            server ${server_ip}:8000;
            vhost default {
                tls_certificate ${tempesta_workdir}/tempesta.crt;
                tls_certificate_key ${tempesta_workdir}/tempesta.key;
                tls_match_any_server_name;
            }

            health_stat 200 5*;
        """
        if self._testMethodName == self.test_cached_responses_included.__name__:
            tempesta_config += """
                cache 1;
                cache_fulfill * *;
            """
        self.tempesta["config"] = tempesta_config
        super().setUp()

    def test_smoke(self):
        self.start_all_services()
        c = self.get_client("deproxy")
        s = self.get_server("deproxy")
        tfw = self.get_tempesta()

        for status in [400, 200, 500, 502, 504, 200, 404]:
            s.set_response(f"HTTP/1.1 {status} FOO\r\nContent-Length: 0\r\n\r\n")
            c.send_request(c.simple_get, expected_status_code=str(status))

        tfw.get_stats()
        self.assertEqual(tfw.stats.health_statuses[200], 2)
        self.assertEqual(tfw.stats.health_statuses[5], 3)

    def test_cached_responses_included(self):
        self.start_all_services()
        c = self.get_client("deproxy")
        s = self.get_server("deproxy")
        tfw = self.get_tempesta()

        s.set_response(f"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        for status in range(3):
            c.send_request(c.simple_get, expected_status_code="200")

        tfw.get_stats()
        # cached responses are accounted
        self.assertEqual(tfw.stats.health_statuses[200], 3)
        self.assertEqual(tfw.stats.cache_hits, 2)
        self.assertEqual(tfw.stats.cache_misses, 1)


@parameterize_class(
    [
        {"name": "Http", "clients": [DEPROXY_CLIENT]},
        {"name": "H2", "clients": [DEPROXY_CLIENT_H2]},
    ]
)
class TestHealthStatServer(tester.TempestaTest):
    tempesta = {
        "config": """
            listen 80;
            listen 443 proto=h2;
            server ${server_ip}:8000;
            vhost default {
                tls_certificate ${tempesta_workdir}/tempesta.crt;
                tls_certificate_key ${tempesta_workdir}/tempesta.key;
                tls_match_any_server_name;
            }

            health_stat_server 400 5*;
            server_failover_http 404 999 999;
        """,
    }

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
        },
    ]

    def test_smoke(self):
        self.start_all_services()
        c = self.get_client("deproxy")
        s = self.get_server("deproxy")
        stats = tempesta.ServerStats(
            self.get_tempesta(), "default", tf_cfg.cfg.get("Server", "ip"), 8000
        )

        for status in [200, 400, 500, 502, 504, 400, 404, 403]:
            s.set_response(f"HTTP/1.1 {status} FOO\r\nContent-Length: 0\r\n\r\n")
            c.send_request(c.simple_get, expected_status_code=str(status))

        stats.collect()
        # 200 is always enabled, even if another status codes are configured explicitly
        self.assertEqual(stats.health_statuses[200], 1)
        self.assertEqual(stats.health_statuses[400], 2)
        self.assertEqual(stats.health_statuses[5], 3)
        # server_failover_http works too for health monitoring
        self.assertEqual(stats.health_statuses[404], 1)


class TestHealthMonitorForDisabledServer(tester.TempestaTest):
    tempesta = {
        "config": """
            listen 80;
            health_check h_monitor1 {
                request "GET / HTTP/1.1\r\n\r\n";
                request_url "/";
                resp_code   200;
                resp_crc32  auto;
                timeout     1;
            }

            srv_group srv_grp1 {
                server ${server_ip}:8000;
                health h_monitor1;
            }

            vhost srv_grp1{
                proxy_pass srv_grp1;
            }

            http_chain {
                -> srv_grp1;
            }
        """
    }

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n\r\n",
        },
    ]

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        }
    ]

    def test(self):
        """
        This test reproduce crash from #2066 issue in Tempesta FW:
        When health monitor is enabled Tempesta FW sends request to
        server to check it status every @timeout seconds.
        Since drop_conn_when_receiving_data is set to True, server
        drops requests from Tempesta FW. Tempesta FW tries to resend
        request and because health motinor requests have no connection
        pointer kernel BUG occurs.
        """
        self.start_all_services()
        s = self.get_server("deproxy")
        s.drop_conn_when_receiving_data = True
        time.sleep(1)


class TestHmMalformedResponse(tester.TempestaTest):
    """
    Test for issue #2147, malformed HM respose led to crash.
    Such message should be dropped and event should be logged.
    """

    tempesta = {
        "config": """
                listen 80;

                server_failover_http 404 3 10;

                health_check hm0 {
                    request         "GET / HTTP/1.0\r\n\r\n";
                    request_url     "/";
                    resp_code       200;
                    resp_crc32  0x31f37e9f;
                    timeout         1;
                }

                srv_group main {
                server ${server_ip}:8080;

                health hm0;
                }
        """
    }

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8080",
            "response": "static",
            "response_content": "HTTP/1.0 200 OK\r\nCon tent-Length:5\r\n\r\nHello",
        },
    ]

    def setUp(self):
        super().setUp()
        self.klog = dmesg.DmesgFinder(disable_ratelimit=True)
        self.assert_msg = "Expected nums of warnings in `journalctl`: {exp}, but got {got}"
        # Cleanup part
        self.addCleanup(self.cleanup_klog)

    def cleanup_klog(self):
        if hasattr(self, "klog"):
            del self.klog

    def test(self):
        """
        Waiting for at list one response.
        """
        self.start_all_services(client=False)
        server = self.get_server("deproxy")

        util.wait_until(lambda: len(server.requests) != 1)

        warning = "Health Monitor response malformed"
        self.assertTrue(self.klog.find(warning, dmesg.amount_positive))
