__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import asyncio
import os
import unittest
from pathlib import Path

from framework.helpers import dmesg, networker, remote, tf_cfg
from framework.test_suite import tester

TEMPESTA_IP = tf_cfg.cfg.get("Tempesta", "ip")
DURATION = int(tf_cfg.cfg.get("General", "duration"))
MHDDOS_DIR = os.path.join("tools/mhddos")
PROXY_PATH = f"{MHDDOS_DIR}/files/proxies.txt"
MHDDOS_PATH = f"{MHDDOS_DIR}/start.py"
THREADS = int(tf_cfg.cfg.get("General", "stress_threads"))
CONNS = int(tf_cfg.cfg.get("General", "concurrent_connections"))
RPC = int(tf_cfg.cfg.get("General", "stress_requests_count"))


# NGINX backend config with 200 response
NGINX_CONFIG = """
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
            return 200;
        }

        location /nginx_status {
            stub_status on;
        }
    }
}
"""


@unittest.skipIf(
    TEMPESTA_IP.startswith("127."), "Please don't use loopback interface for this test."
)
@unittest.skipIf(not TEMPESTA_IP.startswith("192."), "This test doesn't work on SUT.")
class TestDDoSL7(tester.TempestaTest):
    clients = [
        {
            "id": f"mhddos",
            "type": "external",
            "binary": "python3",
            "cmd_args": "",
        },
        {"id": "curl", "type": "curl", "http2": False, "ssl": True},
    ]

    tempesta = {
        "config": f"""
listen 80 proto=http;
listen 443 proto=h2,https;

cache 2;
cache_fulfill * *;
cache_methods GET HEAD;
cache_ttl 3600;

access_log dmesg;
keepalive_timeout 15;

frang_limits {{
    request_rate {int(RPC / 2)};
    request_burst {int(RPC / 10)};
    tcp_connection_rate {int(CONNS / 2)};
    tcp_connection_burst {int(CONNS / 10)};
    concurrent_tcp_connections {int(CONNS / 2)};
    client_header_timeout 20;
    client_body_timeout 10;
    http_uri_len 1024;
    http_hdr_len 256;
    http_ct_required false;
    http_ct_vals "text/plain" "text/html" "application/json" "application/xml";
    http_header_chunk_cnt 10;
    http_body_chunk_cnt 0;
    http_resp_code_block 403 404 502 5 1;
    http_method_override_allowed true;
    http_methods head post put get;
    http_strict_host_checking true;

}}

# Allow only following characters in URI: %+,/a-zA-Z0-9&?:-.[]_=
# These are tested with the WordPress admin panel.
http_uri_brange 0x25 0x2b 0x2c 0x2f 0x41-0x5a 0x61-0x7a 0x30-0x39 0x26 0x3f 0x3a 0x2d 0x2e 0x5b 0x5d 0x5f 0x3d;

health_stat 3* 4* 5*;
health_stat_server 3* 4* 5*;

block_action attack drop;
block_action error reply;

# Make WordPress to work over TLS.
# See https://tempesta-tech.com/knowledge-base/WordPress-tips-and-tricks/
req_hdr_add X-Forwarded-Proto "https";

resp_hdr_set Strict-Transport-Security "max-age=31536000; includeSubDomains";

# Remove the proxy header to mitigate the httpoxy vulnerability
# See https://httpoxy.org/
req_hdr_set Proxy;

tls_certificate ${{tempesta_workdir}}/tempesta.crt;
tls_certificate_key ${{tempesta_workdir}}/tempesta.key;
tls_match_any_server_name;

srv_group main {{server ${{server_ip}}:8000 conns_n=128;}}

vhost tempesta-tech.com {{proxy_pass main;}}

http_chain {{
	# Redirect old URLs from the old static website
	uri == "/index"		-> 301 = /;
	uri == "/development-services" -> 301 = /network-security-performance-analysis;

	# Disable PHP dynamic logic for caching
	# See https://www.varnish-software.com/developers/tutorials/configuring-varnish-wordpress/
	uri == "/wp-admin*" -> cache_disable;
	uri == "/wp-comments-post.php*" -> cache_disable;

	# RSS feed /comments/feed/ is cached as other resource for 1 hour,
	# defined by the global cache_ttl policy.

	# Proably outdated redirects
	uri == "/index.html"	-> 301 = /;
	uri == "/services"	-> 301 = /development-services;
	uri == "/services.html"	-> 301 = /development-services;
	uri == "/c++-services"	-> 301 = /development-services;
	uri == "/company.html"	-> 301 = /company;
	uri == "/blog/fast-programming-languages-c-c++-rust-assembly" -> 301 = /blog/fast-programming-languages-c-cpp-rust-assembly;

	-> tempesta-tech.com;
}}
"""
    }

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG,
        }
    ]

    proxies = []

    interface = tf_cfg.cfg.get("Server", "aliases_interface")

    backend_page_size = 114842  # this is an arbitrary number.

    async def make_response(self, curl, uri: str) -> None:
        curl.headers["Host"] = "tempesta-tech.com"
        curl.set_uri(uri)
        curl.start()
        await self.wait_while_busy(curl)
        curl.stop()

    @classmethod
    async def asyncSetUpClass(cls):
        super().setUpClass()
        cls.addClassCleanup(cls.cleanup_proxies)

        # create 250 IP addresses
        cls.networker = networker.NetWorker(node=remote.client)
        for n in range(1, 250):
            (_, ip) = cls.networker.create_interface(n)
            cls.networker.create_route(ip)
            cls.proxies.append(ip)

        ips_str = "\n".join(cls.proxies)
        remote.client.mkdir(f"{MHDDOS_DIR}/files/")
        remote.client.run_cmd(f'echo "{ips_str}" > {PROXY_PATH}')

    async def asyncSetUp(self):
        await super().asyncSetUp()
        self.create_large_page()
        self.addCleanup(self.remove_large_page)

    @property
    def large_page_path(self):
        return Path(tf_cfg.cfg.get("Server", "resources")) / "large.html"

    def create_large_page(self):
        server = self.get_server("nginx")
        server.node.run_cmd(f"fallocate -l {self.backend_page_size} {self.large_page_path}")

    def remove_large_page(self):
        server = self.get_server("nginx")
        server.node.remove_file(str(self.large_page_path))

    @classmethod
    def cleanup_proxies(cls):
        cls.networker.remove_routes(cls.proxies)
        cls.networker.remove_interfaces(cls.proxies)

    @dmesg.limited_rate_on_tempesta_node
    async def test(self):
        """
        I used the mhddos utility for testing.
        It is implemented using python3 and has been reworked to match our requirements.
        Unsupported http versions removed, host, if-none-match headers fixed, etc.

        The current work principle:
            -> create multiple interfaces for IP addresses
            -> set the rpc, duration, threads parameters
            -> create HttpFlood objects (according to the number of threads)
            -> each thread chooses (randomly) an attack method (from a predefined list)
            -> each thread opens a connection with a random IP address
            -> sends requests according to the logic of a method
            -> repeating.

        Setup for testing:
            - TempestaFW is on a separate VM. 8 GB memory and 6 cores;
            - The attacker and tempesta-tech.com (wordpress) in lxc container are on yet one VM;

        I checked frang with block_action directives. Results:
        - block_action attack drop and ip_block on are the most effective combination for protection.
            - if the attacker exceeds the limits, then we block this IP
              and the memory consumption will be small (I got about 100 MB)
              for both small (5-20 rate) and large limits (100+ rate);
            - if the client does not exceed the limits, then we block IP
              addresses through other directives. For example: http_resp_code_blocks,
              http_strict_host_checking, http_ct_vals etc. The memory consumption
              is higher, but less than 500 MB for me;

        - block_action attack reply\drop and ip_block off are not effective for protection,
          because a lot of memory is consumed. If the attacker exceeds the limits, TempestaFW
          eventually consumes all available memory and my VM was shutdown.
          Perhaps this problem will be solved after closing issues #2284 and #2286.
          It took me 2-5 minutes to use all available resources (depends on the methods).

        Getting a response from the cache/upstream:
          - responses from the cache were returned without delay under any load and
            configuration (if there are enough resources on TempestaFW VM);
          - upstream responses without ip_block on require a very long time.
            Our website with wordpress and lxc was used as the upstream.
            The response was returned up to 30 seconds. Probably lxc did not
            have enough resources, because the attacker used all available resources.

        What can be improved:
          - L4 tests from this tool;
          - checks in L7 for the legitimate client (after fix 2284 and 2286);
          - add a compare with Nginx. I used default config and with request/connection
            limit, but I didn't get a lot of resource consumption. Probably, this tool
            requires to update for that;
          - probably upstream should move to a separate VM. The lack of resources
            should be excluded;
        """
        await self.start_all_services(client=False)

        client = self.get_client("mhddos")
        curl = self.get_client("curl")
        tempesta = self.get_tempesta()

        # save and check a response in cache before attack
        for _ in range(2):
            await self.make_response(curl, "/large.html")
            self.assertEqual(curl.last_response.status, 200)
        await asyncio.sleep(0.2)  # *_burst directives can be equal to 1
        self.assertIsNotNone(
            curl.last_response.headers.get("age", None),
            "TempestaFW didn't return the response from the cache before the attack started.",
        )

        client.options = [
            f"{MHDDOS_PATH} "
            + f"--url https://{TEMPESTA_IP}:443 "
            + f"--hostname tempesta-tech.com "
            + f"--threads {THREADS} "
            + f"--rpc {RPC} "
            + f"--duration {DURATION} "
        ]
        client.start()

        await asyncio.sleep(DURATION / 2)
        # Get a response from the cache after the attack started.
        await self.make_response(curl, "/large.html")
        error_msg = (
            "TempestaFW didn't return the response from the cache after the attack started. "
            "The connection was created during the attack"
        )
        self.assertEqual(curl.last_response.status, 200, error_msg)
        self.assertIsNotNone(curl.last_response.headers.get("age", None), error_msg)
        self.assertGreater(
            DURATION / 2,
            curl.last_stats.get("time_total", DURATION),
            "The time to receive a request from the cache is longer than the attack time.",
        )
        # TODO: https://github.com/tempesta-tech/tempesta-test/issues/38
        #  issue - add checks to receiving a response from upstream

        self.assertTrue(await client.wait_for_finish(timeout=DURATION + 5))
        client.stop()

        tempesta.get_stats()
        self.assertGreater(tempesta.stats.cl_msg_received, 3, "DDoS tool doesn't work.")
