"""
HTTP Stress tests - load Tempesta FW with multiple connections.
"""

import os
import time
from pathlib import Path

from helpers import dmesg, remote, tf_cfg
from helpers.networker import NetWorker
from helpers.deproxy import HttpMessage
from t_frang.frang_test_case import FrangTestCase
from test_suite import marks, tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2026 Tempesta Technologies, Inc."
__license__ = "GPL2"


# Number of open connections
CONCURRENT_CONNECTIONS = int(tf_cfg.cfg.get("General", "concurrent_connections"))
# Number of threads to use for wrk and h2load tests
THREADS = int(tf_cfg.cfg.get("General", "stress_threads"))

# Number of requests to make
REQUESTS_COUNT = int(tf_cfg.cfg.get("General", "stress_requests_count"))
# Time to wait for single request completion
DURATION = int(tf_cfg.cfg.get("General", "duration"))

# MTU values to set for interfaces. 0 - do not change value.
# There was errors when MTU is set to 80 (see Tempesta issue #1703)
# Tempesta -> Client interface
TEMPESTA_TO_CLIENT_MTU = int(tf_cfg.cfg.get("General", "stress_mtu"))
# Tempesta -> Server interface
TEMPESTA_TO_SERVER_MTU = int(tf_cfg.cfg.get("General", "stress_mtu"))
# Server -> Tempesta interface
SERVER_TO_TEMPESTA_MTU = int(tf_cfg.cfg.get("General", "stress_mtu"))

# Backend response content size in bytes
LARGE_CONTENT_LENGTH = int(tf_cfg.cfg.get("General", "stress_large_content_length"))

# NGINX backend config with the large page response
NGINX_LARGE_PAGE_CONFIG = """
pid ${pid};
worker_processes  auto;
#error_log /dev/stdout info;
error_log /dev/null emerg;

events {
    worker_connections   1024;
    use epoll;
}

http {
    keepalive_timeout 65;
    keepalive_requests 100;
    sendfile         on;
    tcp_nopush       on;
    tcp_nodelay      on;

    open_file_cache max=1000;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors off;

    # Disable access log altogether.
    access_log off;

    server {
        listen 8000;

        location / {
            root ${server_resources};
            try_files /large.html =404;
        }
        location /nginx_status {
            stub_status on;
        }
    }
}
"""
# NGINX backend config with 200 response
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
    client_max_body_size 10000M;

    # [ debug | info | notice | warn | error | crit | alert | emerg ]
    # Fully disable log errors.
    error_log /dev/null emerg;

    # Disable access log altogether.
    access_log off;

    server {
        listen        ${server_ip}:8000;

        location / {
            return 200;
        }
        location /nginx_status {
            stub_status on;
        }
    }
}
"""


class LargePageNginxBackendMixin:
    """Mixin that adds `nginx-large-page` backend on 8000 port."""

    nginx_backend_page_size = LARGE_CONTENT_LENGTH

    @property
    def large_page_path(self):
        return Path(tf_cfg.cfg.get("Server", "resources")) / "large.html"

    def setUp(self):
        if self._base:
            self.skipTest("This is an abstract class")
        self.backends = [
            *self.backends[:],
            {
                "id": "nginx-large-page",
                "type": "nginx",
                "port": "8000",
                "status_uri": "http://${server_ip}:8000/nginx_status",
                "config": NGINX_LARGE_PAGE_CONFIG,
            },
        ]
        super().setUp()
        self.create_large_page()
        # Cleanup part
        self.addCleanup(self.remove_large_page)

    def create_large_page(self):
        server = self.get_server("nginx-large-page")
        server.node.run_cmd(f"fallocate -l {self.nginx_backend_page_size} {self.large_page_path}")

    def remove_large_page(self):
        server = self.get_server("nginx-large-page")
        server.node.remove_file(str(self.large_page_path))


class LargePageNginxBackendMixinMTU80(LargePageNginxBackendMixin):
    nginx_backend_page_size = int(LARGE_CONTENT_LENGTH / 16)


class BaseWrk(tester.TempestaTest):
    """Base class for `wrk` stress tests."""

    concurrent_connections = CONCURRENT_CONNECTIONS
    threads = THREADS
    timeout = 20
    duration = DURATION

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.assertTrue(self.wait_all_connections(1))

    def _test_concurrent_connections(self):
        self.start_all()
        wrk = self.get_client("wrk")
        wrk.set_script("foo", content='wrk.method="GET"')
        wrk.connections = self.concurrent_connections
        wrk.duration = int(self.duration)
        wrk.threads = self.threads
        wrk.timeout = 0

        wrk.start()
        self.wait_while_busy(wrk, timeout=self.timeout)
        wrk.stop()

        self.assertGreater(wrk.statuses[200], 0)


class BaseWrkStress(BaseWrk, base=True):
    tempesta = {
        "config": """
            listen 80 proto=http;
            server ${server_ip}:8000;
            cache 0;
            frang_limits {http_strict_host_checking false;}
        """
    }

    clients = [
        {
            "id": "wrk",
            "type": "wrk",
            "addr": "${tempesta_ip}:80/1",
        },
    ]

    @NetWorker.set_mtu(
        nodes=[
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Client", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Server", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.server",
                "destination_ip": tf_cfg.cfg.get("Tempesta", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
        ]
    )
    @dmesg.limited_rate_on_tempesta_node
    def test_concurrent_connections(self):
        self._test_concurrent_connections()


class WrkStress(LargePageNginxBackendMixin, BaseWrkStress):
    """HTTP stress test generated by `wrk` with concurrent connections."""

    pass


class WrkStressMTU80(LargePageNginxBackendMixinMTU80, BaseWrkStress):
    concurrent_connections = CONCURRENT_CONNECTIONS
    threads = THREADS
    timeout = 200
    duration = 100

    """
    Nginx doesn't work with MTU80, so set it to 100 (only
    Tempesta FW works with MTU80.
    """

    @NetWorker.set_mtu(
        nodes=[
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Client", "ip"),
                "mtu": 80,
            },
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Server", "ip"),
                "mtu": 80,
            },
            {
                "node": "remote.server",
                "destination_ip": tf_cfg.cfg.get("Tempesta", "ip"),
                "mtu": 80,
            },
        ],
        disable_pmtu=True,
    )
    @dmesg.limited_rate_on_tempesta_node
    def test_concurrent_connections(self):
        self._test_concurrent_connections()


class TlsWrkStressBase:
    """Base class for `wrk` tls stress tests."""

    tempesta = {
        "config": """
        listen 443 proto=https;
        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;
        frang_limits {http_strict_host_checking false;}
        server ${server_ip}:8000;
        cache 0;
        """
    }

    clients = [
        {
            "id": "wrk",
            "type": "wrk",
            "ssl": True,
            "addr": "${tempesta_ip}:443",
        },
    ]


class TlsWrkStress(LargePageNginxBackendMixin, TlsWrkStressBase, BaseWrkStress):
    """HTTPS stress test generated by `wrk` with concurrent connections."""

    pass


class TlsWrkStressDocker(TlsWrkStressBase, BaseWrk, check_memleak=True):
    """
    HTTPS stress test generated by `wrk` with concurrent connections and
    docker backend. This test was implemented to reproduce memory leak
    during tls encryption. Docker backend sends response with
    SKBTX_SHARED_FRAG shared flag, Tempesta FW should copy such skbs,
    and there was a memory leak during new skb allocation.
    """

    backends = [
        {
            "id": "python_hello",
            "type": "docker",
            "image": "python",
            "ports": {8000: 8000},
            "cmd_args": "hello.py --body %s -H '%s'" % ("a" * 10000, "b: " + "b" * 50000),
        }
    ]

    @NetWorker.set_mtu(
        nodes=[
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Client", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Server", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.server",
                "destination_ip": tf_cfg.cfg.get("Tempesta", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
        ]
    )
    @dmesg.limited_rate_on_tempesta_node
    def test_concurrent_connections(self):
        self._test_concurrent_connections()


class TlsWrkStressMTU80(LargePageNginxBackendMixinMTU80, TlsWrkStressBase, BaseWrkStress):
    concurrent_connections = CONCURRENT_CONNECTIONS
    threads = THREADS
    timeout = 200
    duration = 100

    @NetWorker.set_mtu(
        nodes=[
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Client", "ip"),
                "mtu": 80,
            },
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Server", "ip"),
                "mtu": 80,
            },
            {
                "node": "remote.server",
                "destination_ip": tf_cfg.cfg.get("Tempesta", "ip"),
                "mtu": 80,
            },
        ],
        disable_pmtu=True,
    )
    @dmesg.limited_rate_on_tempesta_node
    def test_concurrent_connections(self):
        self._test_concurrent_connections()


class BaseCurlStress(LargePageNginxBackendMixin, tester.TempestaTest, base=True):
    """Base class for HTTPS ans HTTP/2 stress tests with `curl`."""

    tempesta_tmpl = """
        listen 443 proto=%s;
        server ${server_ip}:8000;
        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;
        frang_limits {http_strict_host_checking false;}
        cache 0;
    """

    clients = [
        # Client to make a single request
        {
            "id": "single",
            "type": "curl",
            "uri": f"/1",
            "headers": {
                "Connection": "close",
            },
            "cmd_args": (f" --max-time {DURATION}"),
            "disable_output": True,
        },
        # Client to request URLs (/1 /2 ..) sequentially
        {
            "id": "sequential",
            "type": "curl",
            "uri": f"/[1-{REQUESTS_COUNT}]",
            "headers": {
                "Connection": "close",
            },
            "cmd_args": (f" --max-time {DURATION}"),
            "disable_output": True,
        },
        # Client to request URLs (/1 /2 ..) in a pipilene
        {
            "id": "pipelined",
            "type": "curl",
            "uri": f"/[1-{REQUESTS_COUNT}]",
            "cmd_args": (f" --max-time {DURATION}"),
            "disable_output": True,
        },
        # Client to request URLs (/1 /2 ..) in parallel
        {
            "id": "concurrent",
            "type": "curl",
            "uri": f"/[1-{REQUESTS_COUNT}]",
            "parallel": CONCURRENT_CONNECTIONS,
            "cmd_args": (f" --max-time {DURATION}"),
            "disable_output": False,
            "dump_headers": False,
        },
    ]

    def setUp(self):
        if self._base:
            self.skipTest("This is an abstract class")
        self.tempesta = {
            "config": self.tempesta_tmpl % (self.proto),
        }
        super().setUp()

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.assertTrue(self.wait_all_connections(1))

    def make_requests(self, client_id):
        client = self.get_client(client_id)
        self.start_all()
        client.start()
        self.wait_while_busy(client)
        client.stop()
        self.assertEqual(client.statuses[200], REQUESTS_COUNT)
        if client.last_response:
            self.assertFalse(client.last_response.stderr)

    def range_requests(self, uri_is_same):
        """Send requests sequentially, stop on error."""
        self.start_all()
        client = self.get_client("single")
        started = time.time()
        delta = 0

        for i in range(1, REQUESTS_COUNT + 1):
            delta = time.time() - started
            client.set_uri("/" if uri_is_same else f"/{i}")
            client.start()
            self.wait_while_busy(client)
            client.stop()

            response = client.last_response
            self.assertFalse(response.stderr, f"Error after {delta} seconds and {i} requests.")
            self.assertEqual(response.status, 200)
            self.assertEqual(
                int(client.last_response.headers["content-length"]),
                LARGE_CONTENT_LENGTH,
            )

    @NetWorker.set_mtu(
        nodes=[
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Client", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Server", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.server",
                "destination_ip": tf_cfg.cfg.get("Tempesta", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
        ]
    )
    def test_range_requests(self):
        self.range_requests(False)

    @NetWorker.set_mtu(
        nodes=[
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Client", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Server", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.server",
                "destination_ip": tf_cfg.cfg.get("Tempesta", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
        ]
    )
    def test_sequential_requests(self):
        """Send requests sequentially, continue on errors."""
        self.make_requests("sequential")

    @NetWorker.set_mtu(
        nodes=[
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Client", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Server", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.server",
                "destination_ip": tf_cfg.cfg.get("Tempesta", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
        ]
    )
    def test_pipelined_requests(self):
        """Send requests in a single pipeline."""
        self.make_requests("pipelined")

    @NetWorker.set_mtu(
        nodes=[
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Client", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Server", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.server",
                "destination_ip": tf_cfg.cfg.get("Tempesta", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
        ]
    )
    def test_concurrent_requests(self):
        """Send requests in parallel."""
        self.make_requests("concurrent")


@marks.parameterize_class(
    [
        {"name": "Http", "proto": "https"},
        {"name": "H2", "proto": "h2"},
    ]
)
class TestTdbStress(LargePageNginxBackendMixin, tester.TempestaTest):
    """HTTP TDB stress test generated by `curl`."""

    tempesta_tmpl = """
        listen 443 proto=%s;
        listen 80;
        server ${server_ip}:8000;
        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;
        cache 2;
        cache_fulfill * *;
        cache_purge immediate;
        cache_purge_acl ${client_ip};
        frang_limits {http_strict_host_checking false; http_methods get purge;}
    """

    nginx_backend_page_size = 1048576

    clients = [
        {
            "id": "concurrent",
            "type": "curl",
            "uri": f"/[1-255]",
            "parallel": CONCURRENT_CONNECTIONS,
            "cmd_args": (f" --max-time {DURATION}"),
            "disable_output": True,
            "dump_headers": False,
        },
        {
            "id": "concurrent-purge",
            "type": "curl",
            "uri": f"/[1-255]",
            "parallel": CONCURRENT_CONNECTIONS,
            "cmd_args": (f" --max-time {DURATION}"),
            "disable_output": True,
            "dump_headers": False,
            "method": "PURGE",
        },
    ]

    def setUp(self):
        if self._base:
            self.skipTest("This is an abstract class")
        self.tempesta = {
            "config": self.tempesta_tmpl % (self.proto),
        }
        if self.proto == "h2":
            self.clients = [{**client, "http2": True} for client in self.clients]
        super().setUp()

    def test_cache_eviction_tdb(self):
        """
        Client sends many requests to different uris to fill tdb cache.
        Then client sends many PURGE requests to clear the cache.
        This is stability test, Tempesta must not crash and shutdown successfully.
        NOTE: Do not expect same behavior on each test run, count of "out of free space"
        error messages can be different on each run.
        """
        expected_warning = "ERROR: out of free space"
        client = self.get_client("concurrent")
        client_purge = self.get_client("concurrent-purge")
        server = self.get_server("nginx-large-page")
        tempesta = self.get_tempesta()
        # Test must ignore ERROR in dmesg, or it will get fail in tearDown.
        self.oops_ignore.append("ERROR")

        self.start_all_services(client=False)

        for step in range(20):
            client.set_uri(f"/{step}/[1-256]")
            client.start()
            self.wait_while_busy(client)
            client.stop()
            tempesta.get_stats()
            self.assertGreater(tempesta.stats.cache_objects, 0)

            client_purge.set_uri(f"/{step}/[1-256]")
            client_purge.start()
            self.wait_while_busy(client_purge)
            client_purge.stop()
            tempesta.get_stats()
            self.assertEqual(tempesta.stats.cache_objects, 0)

        server.get_stats()
        self.assertGreater(server.requests, 0)
        self.assertTrue(
            self.loggers.dmesg.find(expected_warning, cond=dmesg.amount_positive),
            f"Warning '{expected_warning}' wasn't found",
        )


class TlsCurlStress(BaseCurlStress):
    """HTTPS stress test generated by `curl`."""

    proto = "https"

    def setUp(self):
        self.clients = [{**client, "ssl": True} for client in self.clients]
        super().setUp()


class H2CurlStress(BaseCurlStress):
    """HTTP/2 stress test generated by `curl`."""

    proto = "h2"

    def setUp(self):
        self.clients = [{**client, "http2": True} for client in self.clients]
        super().setUp()


class H2LoadStressBase(tester.TempestaTest):
    """
    HTTP/2 stress test generated by`h2load`,
    with multiple streams per connection.
    """

    tempesta = {
        "config": """
            listen 443 proto=h2;
            server ${server_ip}:8000;
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;
            max_concurrent_streams 10000;
            frang_limits {http_strict_host_checking false;}
        """
    }

    clients = [
        {
            "id": "h2load",
            "type": "external",
            "binary": "h2load",
            "ssl": True,
            "cmd_args": "",
        },
    ]

    def start_all(self, cache_mode):
        tempesta: Tempesta = self.get_tempesta()
        tempesta.config.defconfig += cache_mode

        h2load = self.get_client("h2load")
        h2load.options = [
            f" https://%s --clients %s --threads %s --max-concurrent-streams %s --duration %s"
            % (
                tf_cfg.cfg.get("Tempesta", "ip"),
                self.concurrent_connections,
                self.threads,
                self.request_count,
                self.duration,
            )
        ]

        self.start_all_servers()
        self.start_tempesta()
        self.assertTrue(self.wait_all_connections(1))


class H2LoadStress(LargePageNginxBackendMixin, H2LoadStressBase):
    concurrent_connections = CONCURRENT_CONNECTIONS
    threads = THREADS
    request_count = REQUESTS_COUNT
    timeout = 20
    duration = DURATION

    @marks.Parameterize.expand(
        [
            marks.Param(name="no_cache", cache_mode="cache 0;\r\n"),
            marks.Param(name="with_cache", cache_mode="cache 2;\r\ncache_fulfill * *;\r\n"),
        ]
    )
    @NetWorker.set_mtu(
        nodes=[
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Client", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Server", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.server",
                "destination_ip": tf_cfg.cfg.get("Tempesta", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
        ]
    )
    @dmesg.limited_rate_on_tempesta_node
    def test(self, name, cache_mode):
        self.start_all(cache_mode)
        client = self.get_client("h2load")
        client.start()
        self.wait_while_busy(client, timeout=self.timeout)
        client.stop()
        self.assertEqual(client.returncode, 0)
        self.assertNotIn(" 0 2xx, ", client.response_msg)


class H2LoadStressMTU80(LargePageNginxBackendMixinMTU80, H2LoadStressBase):
    concurrent_connections = int(CONCURRENT_CONNECTIONS / 2)
    threads = THREADS
    request_count = REQUESTS_COUNT
    timeout = 200
    duration = 100

    @marks.Parameterize.expand(
        [
            marks.Param(name="no_cache", cache_mode="cache 0;\r\n"),
            marks.Param(name="with_cache", cache_mode="cache 2;\r\ncache_fulfill * *;\r\n"),
        ]
    )
    @NetWorker.set_mtu(
        nodes=[
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Client", "ip"),
                "mtu": 80,
            },
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Server", "ip"),
                "mtu": 80,
            },
            {
                "node": "remote.server",
                "destination_ip": tf_cfg.cfg.get("Tempesta", "ip"),
                "mtu": 80,
            },
        ],
        disable_pmtu=True,
    )
    @dmesg.limited_rate_on_tempesta_node
    def test(self, name, cache_mode):
        self.start_all(cache_mode)
        client = self.get_client("h2load")
        client.duration = self.duration
        client.start()
        self.wait_while_busy(client, timeout=self.timeout)
        client.stop()
        self.assertEqual(client.returncode, 0)
        self.assertNotIn(" 0 2xx, ", client.response_msg)


class RequestStress(tester.TempestaTest):
    tempesta = {
        "config": """
    listen 80;
    frang_limits {
        http_strict_host_checking false;
        http_methods POST PUT GET DELETE;
        }
    listen 443 proto=https;
    listen 4433 proto=h2;
    server ${server_ip}:8000;

    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;
    tls_match_any_server_name;
    max_concurrent_streams 10000;
    cache 0;
    """
    }

    location = tf_cfg.cfg.get("Client", "workdir")
    fullname = os.path.join(location, "long_body.bin")

    clients = [
        {
            "id": "wrk-http",
            "type": "wrk",
            "addr": "${tempesta_ip}:80",
        },
        {
            "id": "wrk-https",
            "type": "wrk",
            "ssl": True,
            "addr": "${tempesta_ip}:443",
        },
        {
            "id": "h2load",
            "type": "external",
            "binary": "h2load",
            "ssl": True,
            "cmd_args": (
                " https://${tempesta_ip}:4433"
                f" --clients {CONCURRENT_CONNECTIONS}"
                f" --threads {THREADS}"
                f" --max-concurrent-streams {REQUESTS_COUNT}"
                f" --duration {DURATION}"
                f" --data={fullname}"
            ),
        },
    ]

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG,
        },
    ]

    def setUp(self):
        remote.client.copy_file(self.fullname, "x" * LARGE_CONTENT_LENGTH)
        super().setUp()
        # Cleanup part
        self.addCleanup(self.cleanup_test_file)

    def cleanup_test_file(self):
        if not remote.DEBUG_FILES:
            remote.client.run_cmd(f"rm {self.fullname}")

    @NetWorker.set_mtu(
        nodes=[
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Client", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Server", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.server",
                "destination_ip": tf_cfg.cfg.get("Tempesta", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
        ]
    )
    @dmesg.limited_rate_on_tempesta_node
    def _test_wrk(self, client_id: str, method: str):
        """
        HTTP stress test generated by `wrk` with concurrent connections and large body in request.
        """
        self.start_all_services(client=False)
        client = self.get_client(client_id)
        client.set_script(
            script="request_1k",
            content=(
                f'wrk.method = "{method}"\n'
                + 'wrk.path = "/"\n'
                + "wrk.header = {\n"
                + "}\n"
                + f'wrk.body = "{"x" * LARGE_CONTENT_LENGTH}"\n'
            ),
        )
        client.connections = CONCURRENT_CONNECTIONS
        client.duration = int(DURATION)
        client.threads = THREADS
        client.timeout = 0

        client.start()
        self.wait_while_busy(client)
        client.stop()

        self.assertGreater(client.statuses[200], 0, "Client has not received 200 responses.")

    @NetWorker.set_mtu(
        nodes=[
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Client", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Server", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.server",
                "destination_ip": tf_cfg.cfg.get("Tempesta", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
        ]
    )
    @dmesg.limited_rate_on_tempesta_node
    def _test_h2load(self, method: str):
        self.start_all_services(client=False)
        client = self.get_client("h2load")
        client.options[0] += f' -H ":method:{method}"'

        client.start()
        self.wait_while_busy(client)
        client.stop()

        self.assertEqual(client.returncode, 0)
        self.assertNotIn(" 0 2xx, ", client.response_msg)

    def test_http_post_request(self):
        self._test_wrk(client_id="wrk-http", method="POST")

    def test_http_put_request(self):
        self._test_wrk(client_id="wrk-http", method="PUT")

    def test_https_post_request(self):
        self._test_wrk(client_id="wrk-https", method="POST")

    def test_https_put_request(self):
        self._test_wrk(client_id="wrk-https", method="PUT")

    def test_h2_post_request(self):
        self._test_h2load(method="POST")

    def test_h2_put_request(self):
        self._test_h2load(method="PUT")


class TestContinuationFlood(tester.TempestaTest):
    """
    Test stability against CONTINUATION frame flood.
    """

    clients = [
        {
            "id": "gflood",
            "type": "external",
            "binary": "gflood",
            "ssl": True,
            "cmd_args": "-address ${tempesta_ip}:443 -host tempesta-tech.com -threads 4 -connections 10000 -streams 100 -headers_cnt 7",
        },
    ]

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG,
        }
    ]

    tempesta = {
        "config": """
        listen 443 proto=h2;

        server ${server_ip}:8000;

        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;
        cache 0;
    """
    }

    @dmesg.limited_rate_on_tempesta_node
    def test(self):
        client = self.get_client("gflood")

        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.wait_while_busy(client)
        client.stop()
        self.assertEqual(0, client.returncode)


class TestRequestsUnderCtrlFrameFlood(FrangTestCase):
    """
    Test ability to handle requests from the client
    under control frames frame flood.
    Also check that there is no kernel BUGS and WARNINGs
    under flood.
    """

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + f"Date: {HttpMessage.date_time_string()}\r\n"
                + "Server: debian\r\n"
                + "Content-Length: 0\r\n\r\n"
            ),
        }
    ]

    tempesta = {
        "config": """
        listen 443 proto=h2;

        server ${server_ip}:8000;

        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;
        cache 0;
    """
    }

    clients = [
        {
            "id": "ctrl_frames_flood",
            "type": "external",
            "binary": "ctrl_frames_flood",
            "ssl": True,
            "cmd_args": "",
        },
    ]

    def _test(self, cmd_args):
        self.start_all_services(client=False)
        flood_client = self.get_client("ctrl_frames_flood")
        flood_client.options = [cmd_args % tf_cfg.cfg.get("Tempesta", "ip")]
        flood_client.start()
        self.wait_while_busy(flood_client)
        flood_client.stop()

    def _check_ping_frame_exceeded(self):
        tempesta = self.get_tempesta()
        tempesta.get_stats()
        self.assertEqual(tempesta.stats.cl_ping_frame_exceeded, 100)

    def _check_prio_frame_exceeded(self):
        tempesta = self.get_tempesta()
        tempesta.get_stats()
        self.assertEqual(tempesta.stats.cl_priority_frame_exceeded, 100)

    def _check_settings_frame_exceeded(self):
        tempesta = self.get_tempesta()
        stats = tempesta.get_stats()
        self.assertEqual(tempesta.stats.cl_settings_frame_exceeded, 100)

    def _check_wnd_update_frame_exceeded(self):
        tempesta = self.get_tempesta()
        stats = tempesta.get_stats()
        self.assertEqual(tempesta.stats.cl_wnd_update_frame_exceeded, 100)

    def _check_rst_frame_exceeded(self):
        tempesta = self.get_tempesta()
        stats = tempesta.get_stats()
        self.assertEqual(tempesta.stats.cl_rst_frame_exceeded, 100)

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="PingFlood",
                cmd_args=f"-address %s:443 -threads 4 -connections 100 -ctrl_frame_type ping_frame -frame_count 100000",
                check_func=_check_ping_frame_exceeded,
            ),
            marks.Param(
                name="SettingsFlood",
                cmd_args=f"-address %s:443 -threads 4 -connections 100 -ctrl_frame_type settings_frame -frame_count 100000",
                check_func=_check_settings_frame_exceeded,
            ),
            marks.Param(
                name="WndUpdateFlood",
                cmd_args=f"-address %s:443 -threads 4 -connections 100 -ctrl_frame_type window_update -frame_count 100000",
                check_func=_check_wnd_update_frame_exceeded,
            ),
            marks.Param(
                name="RstFloodByWndUpdate",
                cmd_args=f"-address %s:443 -threads 4 -connections 100 -ctrl_frame_type rapid_reset -rapid_reset_type window_update -frame_count 100000",
                check_func=_check_rst_frame_exceeded,
            ),
            marks.Param(
                name="RstFloodByPriority",
                cmd_args=f"-address %s:443 -threads 4 -connections 100 -ctrl_frame_type rapid_reset -rapid_reset_type priority -frame_count 100000",
                check_func=_check_rst_frame_exceeded,
            ),
            marks.Param(
                name="RstFloodByRst",
                cmd_args=f"-address %s:443 -threads 4 -connections 100 -ctrl_frame_type rapid_reset -rapid_reset_type rst -frame_count 100000",
                check_func=_check_rst_frame_exceeded,
            ),
            marks.Param(
                name="RstFloodByRstBatch",
                cmd_args=f"-address %s:443 -threads 4 -connections 100 -ctrl_frame_type rapid_reset -rapid_reset_type batch -frame_count 100000",
                check_func=_check_rst_frame_exceeded,
            ),
            marks.Param(
                name="RstByHeadersMaxConcurrentStreamsExceeded",
                cmd_args=f"-address %s:443 -threads 4 -connections 100 -ctrl_frame_type rapid_reset -rapid_reset_type headers_by_max_streams_exceeded -frame_count 100000",
                check_func=_check_rst_frame_exceeded,
            ),
            marks.Param(
                name="RstByHeadersInvalidDependency",
                cmd_args=f"-address %s:443 -threads 4 -connections 100 -ctrl_frame_type rapid_reset -rapid_reset_type headers_by_invalid_dependency -frame_count 100000",
                check_func=_check_rst_frame_exceeded,
            ),
            marks.Param(
                name="RstByIncorrectFrameType",
                cmd_args=f"-address %s:443 -threads 4 -connections 100 -ctrl_frame_type rapid_reset -rapid_reset_type incorrect_frame_type -frame_count 100000",
                check_func=_check_rst_frame_exceeded,
            ),
            marks.Param(
                name="RstByIncorrectHeader",
                cmd_args=f"-address %s:443 -threads 4 -connections 100 -ctrl_frame_type rapid_reset -rapid_reset_type incorrect_header -frame_count 100000",
                check_func=_check_rst_frame_exceeded,
            ),
        ]
    )
    @dmesg.unlimited_rate_on_tempesta_node
    def test(self, name, cmd_args, check_func):
        server = self.get_server("deproxy")
        response_body = 2000 * "a"
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Server: Debian\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + f"Content-Length: {len(response_body)}\r\n\r\n"
            + response_body
        )
        self._test(cmd_args)
        check_func(self)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
