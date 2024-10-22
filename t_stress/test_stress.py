"""
HTTP Stress tests - load Tempesta FW with multiple connections.
"""

import os
import time
from pathlib import Path

from helpers import dmesg, remote, tf_cfg
from test_suite import marks, sysnet, tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2024 Tempesta Technologies, Inc."
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


class CustomMtuMixin:
    """Mixin to set interfaces MTU values before test is started."""

    tempesta_to_client_mtu = TEMPESTA_TO_CLIENT_MTU
    tempesta_to_server_mtu = TEMPESTA_TO_SERVER_MTU
    server_to_tempesta_mtu = SERVER_TO_TEMPESTA_MTU

    def setUp(self):
        if self._base:
            self.skipTest("This is an abstract class")
        super().setUp()
        self._prev_mtu = {}
        self.set_mtu(
            node=remote.tempesta,
            destination_ip=tf_cfg.cfg.get("Client", "ip"),
            mtu=self.tempesta_to_client_mtu,
        )
        self.set_mtu(
            node=remote.tempesta,
            destination_ip=tf_cfg.cfg.get("Server", "ip"),
            mtu=self.tempesta_to_server_mtu,
        )
        self.set_mtu(
            node=remote.server,
            destination_ip=tf_cfg.cfg.get("Tempesta", "ip"),
            mtu=self.server_to_tempesta_mtu,
        )
        # Cleanup part
        self.addCleanup(self.cleanup_mtus)

    def cleanup_mtus(self):
        # Restore previous MTU values
        for args in self._prev_mtu.values():
            sysnet.change_mtu(*args)

    def set_mtu(self, node, destination_ip, mtu):
        if mtu:
            dev = sysnet.route_dst_ip(node=node, ip=destination_ip)
            prev = sysnet.change_mtu(node=node, dev=dev, mtu=mtu)
            if not dev in self._prev_mtu:
                self._prev_mtu[dev] = [node, dev, prev]


class BaseWrk(tester.TempestaTest):
    """Base class for `wrk` stress tests."""

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.assertTrue(self.wait_all_connections(1))

    def _test_concurrent_connections(self):
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


class BaseWrkStress(CustomMtuMixin, LargePageNginxBackendMixin, BaseWrk, base=True):
    @dmesg.limited_rate_on_tempesta_node
    def test_concurrent_connections(self):
        self._test_concurrent_connections()


class WrkStress(BaseWrkStress):
    """HTTP stress test generated by `wrk` with concurrent connections."""

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


class WrkStressMTU80(WrkStress):
    tempesta_to_client_mtu = 80
    tempesta_to_server_mtu = 80
    server_to_tempesta_mtu = 80


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


class TlsWrkStress(TlsWrkStressBase, BaseWrkStress):
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

    def test_concurrent_connections(self):
        self._test_concurrent_connections()


class TlsWrkStressMTU80(TlsWrkStress):
    tempesta_to_client_mtu = 80
    tempesta_to_server_mtu = 80
    server_to_tempesta_mtu = 80


class BaseCurlStress(CustomMtuMixin, LargePageNginxBackendMixin, tester.TempestaTest, base=True):
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

        tf_cfg.dbg(2, f"Test completed after {time.time() - started} seconds and {i} requests.")

    def test_range_requests(self):
        self.range_requests(False)

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
        frang_limits {http_strict_host_checking false;}
    """
    proto = "http"

    def test_cache_tdb(self):
        """
        Client sends many requests to different uris to fill tdb cache.
        Tempesta must not receive kernel panic. See issue #1464.
        """
        expected_warning = "ERROR: out of free space"
        client = self.get_client("pipelined")
        server = self.get_server("nginx-large-page")
        # Test must ignore ERROR in dmesg, or it will get fail in tearDown.
        self.oops_ignore.append("ERROR")

        self.get_tempesta().config.set_defconfig(
            self.get_tempesta().config.defconfig.replace(
                "cache 0;", "cache 2;\n\tcache_fulfill * *;\n"
            )
        )
        self.start_all_services(client=False)

        curl_step = 1000  # I receive out of memory for curl if step is too big
        for step in range(1, 1000000, curl_step):
            client.set_uri(f"/[{step}-{step + curl_step}]")
            client.start()
            self.wait_while_busy(client)
            client.stop()

            if self.oops.find(expected_warning, cond=dmesg.amount_positive):
                break

        server.get_stats()
        self.assertGreater(server.requests, 0)
        self.assertTrue(
            self.oops.find(expected_warning, cond=dmesg.amount_positive),
            f"Warning '{expected_warning}' wasn't found",
        )


class TlsCurlStress(BaseCurlStress):
    """HTTPS stress test generated by `curl`."""

    proto = "https"

    def setUp(self):
        self.clients = [{**client, "ssl": True} for client in self.clients]
        super().setUp()

    def test_cache_range_requests(self):
        self.get_tempesta().config.set_defconfig(
            self.get_tempesta().config.defconfig.replace(
                "cache 0;", "cache 2;\n\tcache_fulfill * *;\n"
            )
        )
        self.range_requests(True)


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
            "cmd_args": (
                " https://${tempesta_ip}"
                f" --clients {CONCURRENT_CONNECTIONS}"
                f" --threads {THREADS}"
                f" --max-concurrent-streams {REQUESTS_COUNT}"
                f" --duration {DURATION}"
            ),
        },
    ]

    def start_all(self, cache_mode):
        tempesta: Tempesta = self.get_tempesta()
        tempesta.config.defconfig += cache_mode

        self.start_all_servers()
        self.start_tempesta()
        self.assertTrue(self.wait_all_connections(1))

    @marks.Parameterize.expand(
        [
            marks.Param(name="no_cache", cache_mode="cache 0;\r\n"),
            marks.Param(name="with_cache", cache_mode="cache 2;\r\ncache_fulfill * *;\r\n"),
        ]
    )
    @dmesg.limited_rate_on_tempesta_node
    def test(self, name, cache_mode):
        self.start_all(cache_mode)
        client = self.get_client("h2load")
        client.start()
        self.wait_while_busy(client)
        client.stop()
        self.assertEqual(client.returncode, 0)
        self.assertNotIn(" 0 2xx, ", client.response_msg)


class H2LoadStressMTU80(H2LoadStress):
    tempesta_to_client_mtu = 80
    tempesta_to_server_mtu = 80
    server_to_tempesta_mtu = 80


class RequestStress(CustomMtuMixin, tester.TempestaTest):
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


@marks.parameterize_class(
    [
        {
            "name": "PingFlood",
            "clients": [
                {
                    "id": "ctrl_frames_flood",
                    "type": "external",
                    "binary": "ctrl_frames_flood",
                    "ssl": True,
                    "cmd_args": "-address ${tempesta_ip}:443 -threads 4 -connections 100 -debug 1 -ctrl_frame_type ping_frame -frame_count 100000",
                },
            ],
        },
        {
            "name": "SettingsFlood",
            "clients": [
                {
                    "id": "ctrl_frames_flood",
                    "type": "external",
                    "binary": "ctrl_frames_flood",
                    "ssl": True,
                    "cmd_args": "-address ${tempesta_ip}:443 -threads 4 -connections 100 -debug 1 -ctrl_frame_type settings_frame -frame_count 100000",
                },
            ],
        },
        {
            "name": "RstFlood",
            "clients": [
                {
                    "id": "ctrl_frames_flood",
                    "type": "external",
                    "binary": "ctrl_frames_flood",
                    "ssl": True,
                    "cmd_args": "-address ${tempesta_ip}:443 -threads 4 -connections 100 -debug 1 -ctrl_frame_type rst_stream_frame -frame_count 100000",
                },
            ],
        },
    ]
)
class TestCtrlFrameFlood(tester.TempestaTest):
    """
    Test stability against comtrol frames frame flood.
    """

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

    def setUp(self):
        self.enable_memleak_check()
        super().setUp()

    @dmesg.limited_rate_on_tempesta_node
    def test(self):
        client = self.get_client("ctrl_frames_flood")
        tempesta = self.get_tempesta()

        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.wait_while_busy(client)
        client.stop()

        tempesta.get_stats()
        self.assertGreater(tempesta.stats.wq_full, 0)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
