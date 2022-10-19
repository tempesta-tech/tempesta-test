"""
HTTP Stress tests - load Tempesta FW with multiple connections.
"""

from pathlib import Path
import time

from helpers import remote, sysnet, tf_cfg
from framework import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
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

    def tearDown(self):
        super().tearDown()
        self.remove_large_page()

    def create_large_page(self):
        server = self.get_server("nginx-large-page")
        server.node.run_cmd(
            f"fallocate -l {self.nginx_backend_page_size} {self.large_page_path}"
        )

    def remove_large_page(self):
        server = self.get_server("nginx-large-page")
        server.node.remove_file(str(self.large_page_path))


class CustomMtuMixin:
    """Mixin to set interfaces MTU values before test is started."""

    def setUp(self):
        if self._base:
            self.skipTest("This is an abstract class")
        super().setUp()
        self._prev_mtu = {}
        self.set_mtu(
            node=remote.tempesta,
            destination_ip=tf_cfg.cfg.get("Client", "ip"),
            mtu=TEMPESTA_TO_CLIENT_MTU,
        )
        self.set_mtu(
            node=remote.tempesta,
            destination_ip=tf_cfg.cfg.get("Server", "ip"),
            mtu=TEMPESTA_TO_SERVER_MTU,
        )
        self.set_mtu(
            node=remote.server,
            destination_ip=tf_cfg.cfg.get("Tempesta", "ip"),
            mtu=SERVER_TO_TEMPESTA_MTU,
        )

    def tearDown(self):
        # Restore previous MTU values
        try:
            for args in self._prev_mtu.values():
                sysnet.change_mtu(*args)
        finally:
            super().tearDown()

    def set_mtu(self, node, destination_ip, mtu):
        if mtu:
            dev = sysnet.route_dst_ip(node=node, ip=destination_ip)
            prev = sysnet.change_mtu(node=node, dev=dev, mtu=mtu)
            if not dev in self._prev_mtu:
                self._prev_mtu[dev] = [node, dev, prev]


class BaseWrkStress(
    CustomMtuMixin, LargePageNginxBackendMixin, tester.TempestaTest, base=True
):
    """Base class for `wrk` stress tests."""

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.assertTrue(self.wait_all_connections(1))

    def test_concurrent_connections(self):
        self.start_all()
        wrk = self.get_client("wrk")
        wrk.set_script("foo", content='wrk.method="GET"')
        wrk.connections = CONCURRENT_CONNECTIONS
        wrk.duration = int(DURATION)
        wrk.threads = THREADS
        wrk.timeout = 0

        wrk.start()
        self.wait_while_busy(wrk)
        wrk.stop()

        self.assertGreater(wrk.statuses[200], 0)


class WrkStress(BaseWrkStress):
    """HTTP stress test generated by `wrk` with concurrent connections."""

    tempesta = {
        "config": """
            listen 80 proto=http;
            server ${server_ip}:8000;
            cache 0;
        """
    }

    clients = [
        {
            "id": "wrk",
            "type": "wrk",
            "addr": "${tempesta_ip}:80/1",
        },
    ]


class TlsWrkStress(BaseWrkStress):
    """HTTPS stress test generated by `wrk` with concurrent connections."""

    tempesta = {
        "config": """
        listen 443 proto=https;
        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;
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


class BaseCurlStress(
    CustomMtuMixin, LargePageNginxBackendMixin, tester.TempestaTest, base=True
):
    """Base class for HTTPS ans HTTP/2 stress tests with `curl`."""

    tempesta_tmpl = """
        listen 443 proto=%s;
        server ${server_ip}:8000;
        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;
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
            "disable_output": True,
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
        tf_cfg.dbg(2, f"Number of successful requests: {client.statuses[200]}")
        self.assertFalse(client.last_response.stderr)

    def test_range_requests(self):
        """Send requests sequentially, stop on error."""
        self.start_all()
        client = self.get_client("single")
        started = time.time()
        delta = 0

        for i in range(1, REQUESTS_COUNT + 1):
            delta = time.time() - started
            client.set_uri(f"/{i}")
            client.start()
            self.wait_while_busy(client)
            client.stop()

            response = client.last_response
            self.assertFalse(
                response.stderr, f"Error after {delta} seconds and {i} requests."
            )
            self.assertEqual(response.status, 200)
            self.assertEqual(
                int(client.last_response.headers["content-length"]),
                LARGE_CONTENT_LENGTH,
            )

        tf_cfg.dbg(
            2, f"Test completed after {time.time() - started} seconds and {i} requests."
        )

    def test_sequential_requests(self):
        """Send requests sequentially, continue on errors."""
        self.make_requests("sequential")

    def test_pipelined_requests(self):
        """Send requests in a single pipeline."""
        self.make_requests("pipelined")

    def test_concurrent_requests(self):
        """Send requests in parallel."""
        self.make_requests("concurrent")


class CurlStress(BaseCurlStress):
    """HTTP stress test generated by `curl`."""

    tempesta_tmpl = """
        listen 80 proto=%s;
        server ${server_ip}:8000;
        cache 0;
    """
    proto = "http"


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


class H2LoadStress(CustomMtuMixin, LargePageNginxBackendMixin, tester.TempestaTest):
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
            cache 0;
        """
    }

    clients = [
        {
            "id": "h2load",
            "type": "external",
            "binary": "h2load",
            "ssl": True,
            "cmd_args": (
                " https://${tempesta_ip}"
                f" --clients {CONCURRENT_CONNECTIONS}"
                f" --threads {THREADS}"
                f" --max-concurrent-streams {REQUESTS_COUNT}"
                f" --duration {DURATION}"
            ),
        },
    ]

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.assertTrue(self.wait_all_connections(1))

    def test(self):
        self.start_all()
        client = self.get_client("h2load")
        client.start()
        self.wait_while_busy(client)
        client.stop()
        self.assertEqual(client.returncode, 0)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
