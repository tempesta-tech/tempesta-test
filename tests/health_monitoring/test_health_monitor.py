"""
Tests for health monitoring functionality.
"""

from __future__ import print_function

import asyncio
from collections import defaultdict

from framework.deproxy.deproxy_message import HttpMessage
from framework.helpers import dmesg, tf_cfg
from framework.services import tempesta
from framework.test_suite import marks, tester
from tests.http2_general.test_h2_responses import H2ResponsesPipelinedBase

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024-2025 Tempesta Technologies, Inc."
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

frang_limits {http_strict_host_checking false;}

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
        res = defaultdict(int)
        for _ in range(n):
            curl = self.get_client("curl")
            curl.start()
            curl.wait_for_finish()
            curl.stop()
            res[curl.response_msg[:-1]] += 1
        return res

    async def test(self):
        """Test health monitor functionality with described stages"""
        await self.start_tempesta()

        # 1
        back1 = self.get_server("nginx1")
        back2 = self.get_server("nginx2")
        back3 = self.get_server("nginx3")
        res = self.run_curl(REQ_COUNT)
        self.assertEqual(
            list(res.keys()),
            ["502"],
            f"TempestaFW returned unexpected response statuses - {list(res.keys())}. "
            "But all servers are disabled.",
        )

        # 2
        self.wait_for_server(back1)
        self.wait_for_server(back2)
        res = self.run_curl(REQ_COUNT)
        self.assertEqual(
            list(res.values()),
            [50, 50],
            "TempestaFW forwarded requests without following the `server_failover_http`",
        )

        # 3
        self.wait_for_server(back3)
        res = self.run_curl(REQ_COUNT)
        self.assertGreater(
            res["200"],
            res["502"],
            f"TempestaFW or server are not stable. Response statuses - {res.items()}",
        )

        # 4
        res = self.run_curl(REQ_COUNT)
        self.assertGreater(
            res["200"],
            res["502"],
            f"TempestaFW or server are not stable. Response statuses - {res.items()}",
        )
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


@marks.parameterize_class(
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
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;

            health_stat 200 5*;
        """
        if self._testMethodName == self.test_cached_responses_included.__name__:
            tempesta_config += """
                cache 1;
                cache_fulfill * *;
            """
        self.tempesta["config"] = tempesta_config
        super().setUp()

    async def test_smoke(self):
        await self.start_all_services()
        c = self.get_client("deproxy")
        s = self.get_server("deproxy")
        tfw = self.get_tempesta()

        for status in [400, 200, 500, 502, 504, 200, 404]:
            s.set_response(f"HTTP/1.1 {status} FOO\r\nContent-Length: 0\r\n\r\n")
            await c.send_request(c.simple_get, expected_status_code=str(status))

        tfw.get_stats()
        self.assertEqual(tfw.stats.health_statuses[200], 2)
        self.assertEqual(tfw.stats.health_statuses[5], 3)

    async def test_cached_responses_included(self):
        await self.start_all_services()
        c = self.get_client("deproxy")
        s = self.get_server("deproxy")
        tfw = self.get_tempesta()

        s.set_response(f"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        for status in range(3):
            await c.send_request(c.simple_get, expected_status_code="200")

        tfw.get_stats()
        # cached responses are accounted
        self.assertEqual(tfw.stats.health_statuses[200], 3)
        self.assertEqual(tfw.stats.cache_hits, 2)
        self.assertEqual(tfw.stats.cache_misses, 1)


@marks.parameterize_class(
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
            
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;
            
            srv_group default {
                server ${server_ip}:8000;
            }
            vhost default {
                proxy_pass default;
            }
            http_chain {
                -> default;
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

    async def test_smoke(self):
        await self.start_all_services()
        c = self.get_client("deproxy")
        s = self.get_server("deproxy")
        stats = tempesta.ServerStats(
            self.get_tempesta(), "default", tf_cfg.cfg.get("Server", "ip"), 8000
        )

        for status in [200, 400, 500, 502, 504, 400, 404, 403]:
            s.set_response(f"HTTP/1.1 {status} FOO\r\nContent-Length: 0\r\n\r\n")
            await c.send_request(c.simple_get, expected_status_code=str(status))

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

    async def test(self):
        """
        This test reproduce crash from #2066 issue in Tempesta FW:
        When health monitor is enabled Tempesta FW sends request to
        server to check it status every @timeout seconds.
        Since drop_conn_when_request_received is set to True, server
        drops requests from Tempesta FW. Tempesta FW tries to resend
        request and because health motinor requests have no connection
        pointer kernel BUG occurs.
        """
        await self.start_all_services()
        s = self.get_server("deproxy")
        s.drop_conn_when_request_received = True
        await asyncio.sleep(1)


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

    async def test(self):
        """
        Waiting for at list one response.
        """
        await self.start_all_services(client=False)
        server = self.get_server("deproxy")

        await server.wait_for_requests(1)

        warning = "Health Monitor response malformed"
        self.assertTrue(await self.klog.afind(warning, dmesg.amount_positive))


# CRC tests

"""
Health monitor configuration called "auto" uses "auto" CRC mode.
In this mode CRC for comparation calculated on the fly from
the first server response.
Default HM configuration is "auto".
"""


TEMPESTA_IMPLICIT_AUTO = {
    "config": """
            listen 80;

            server_failover_http 404 3 10;

            srv_group main {
            server ${server_ip}:8080;

            health auto;
            }
    """
}

"""
Auto configuration also can be declared explicitly.
"""
TEMPESTA_EXPLICIT_AUTO = {
    "config": """
            listen 80;

            server_failover_http 404 3 10;

            health_check auto {
                request		"GET / HTTP/1.0\r\n\r\n";
                request_url	"/";
                resp_code	200;
                resp_crc32    auto;
                timeout		3;
            }

            srv_group main {
            server ${server_ip}:8080;

            health auto;
            }
    """
}

"""
Configuration with predefined CRC.
"""

TEMPESTA_PREDEFINED = {
    "config": """
            listen 80;

            server_failover_http 404 3 10;

            health_check hm0 {
                request		"GET / HTTP/1.0\r\n\r\n";
                request_url	"/";
                resp_code	200;
                resp_crc32  0x31f37e9f;
                timeout		3;
            }

            srv_group main {
            server ${server_ip}:8080;

            health hm0;
            }
    """
}


@marks.parameterize_class(
    [
        {
            "name": "ImplicitCRC",
            "tempesta": TEMPESTA_IMPLICIT_AUTO,
            "auto_mode": True,
        },
        {
            "name": "ExplicitCRC",
            "tempesta": TEMPESTA_EXPLICIT_AUTO,
            "auto_mode": True,
        },
        {
            "name": "PredefinedCRC",
            "tempesta": TEMPESTA_PREDEFINED,
            "auto_mode": False,
        },
    ]
)
class TestHmCrc(tester.TempestaTest):
    """
    We check CRC correctness in the following manner:
    - In the auto mode:
      - The first response is for CRC calculation.
      - The second one the same and should be pass CRC check.
      - The third one has different body and in this way
        different CRC.
    - In the predefined mode step 1 is skipped.
    """

    content = [
        "Hello",
        "hELLO",
    ]

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8080",
            "response": "static",
            "response_content": "",
        },
    ]

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.klog = dmesg.DmesgFinder(disable_ratelimit=True)
        self.assert_msg = "Expected nums of warnings in `journalctl`: {exp}, but got {got}"
        # Cleanup part
        self.addCleanup(self.cleanup_klog)

    def cleanup_klog(self):
        if hasattr(self, "klog"):
            del self.klog

    def build_response(self, content):
        content_length = len(content)
        return f"HTTP/1.0 200 OK\r\nContent-Length:{content_length}\r\n\r\n{content}"

    async def test(self):
        """
        Test doesn't use client.
        The scope of interest is a Tempesta<->Server interchange.
        """
        warning = "Response for health monitor"
        n = 1

        server = self.get_server("deproxy")
        await self.start_all_services(client=False)
        server.set_response(self.build_response(self.content[0]))
        # step 1
        if self.auto_mode:
            self.assertTrue(await server.wait_for_requests(n, timeout=12))
            n += 1

        # step 2
        self.assertTrue(await server.wait_for_requests(n, timeout=12))
        n += 1
        self.assertFalse(await self.klog.find(warning))

        # step 3
        server.set_response(self.build_response(self.content[1]))
        self.assertTrue(await server.wait_for_requests(n, timeout=12))
        self.assertTrue(await self.klog.find(warning))


class H2HmResponsesPipelined(H2ResponsesPipelinedBase):
    tempesta = {
        "config": """
            listen 443 proto=h2;
            frang_limits {
                http_strict_host_checking false;
            }
            
            health_check hm0 {
                request         "GET / HTTP/1.0\r\n\r\n";
                request_url     "/";
                resp_code       200;
                resp_crc32  0x31f37e9f;
                timeout         2;
            }

            srv_group default {
                server ${server_ip}:8000 conns_n=1;
                health hm0;
            }
            vhost good {
                proxy_pass default;
            }
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;

            block_action attack reply;
            block_action error reply;
            http_chain {
                host == "bad.com"   -> block;
                                    -> good;
            }
        """
    }

    @marks.Parameterize.expand(
        [
            marks.Param(name="1_hm", hm_num=1),
            marks.Param(name="2_hm", hm_num=2),
            marks.Param(name="3_hm", hm_num=3),
            marks.Param(name="4_hm", hm_num=4),
        ]
    )
    async def test_hm_pipelined(self, name, hm_num):
        requests_n = len(self.get_clients())
        srv = await self.setup_and_start(requests_n + 1)
        self.disable_deproxy_auto_parser()

        srv.set_response(
            "HTTP/1.1 200 OK\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + "Server: debian\r\n"
            + "Content-Length: 0\r\n\r\n"
        )

        clients = self.get_clients()
        for client, i in zip(clients, list(range(1, 5))):
            if i == hm_num:
                self.assertTrue(
                    await srv.wait_for_requests(i),
                    "Server did not receive hm request from TempestaFW.",
                )
                i = i + 1
            client.make_request(self.get_request)
            self.assertTrue(await srv.wait_for_requests(i))

        for client in clients:
            self.assertTrue(await client.wait_for_response())
            self.assertEqual(client.last_response.status, "200")
