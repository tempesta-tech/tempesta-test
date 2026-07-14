"""Slow HTTP *request body* (RUDY / low-and-slow upload) DDoS tests.

Direction: **client → server** — large POST drip-fed one byte at a time.

This is the opposite of CVE-2019-9511 Data Dribble (slow *response* read,
server → client; see ``tests/cve/test_cve.py::TestSlowRead``).

Uses RUDY with HTTP/1.1 and HTTP/2 support
(https://github.com/symstu-tempesta/rudy/tree/symstu/added-http2-support).
Tempesta FW must keep serving legitimate clients while frang
``client_body_timeout`` closes the stalled attack connections.

Deproxy multi-stream H2 upload variant:
``tests/cve/test_cve.py::TestSlowHttp2RequestBody``.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

import asyncio

from framework.helpers import dmesg, tf_cfg
from framework.test_suite import marks, tester

CONNS = int(tf_cfg.cfg.get("General", "concurrent_connections"))

# Body inter-byte delay for RUDY; must exceed frang client_body_timeout.
RUDY_INTERVAL = "5s"
# Frang timeout for incomplete request bodies (seconds).
CLIENT_BODY_TIMEOUT = 2
# Concurrent slow POST workers.
RUDY_CONCURRENTS = min(50, max(CONNS, 10))
# Payload large enough to keep connections open if timeout did not fire.
RUDY_PAYLOAD = "100KB"
# Process budget for the attack (connections should fail earlier via frang).
RUDY_DURATION = 30

RUDY_COMMON = {
    "type": "rudy",
    "uri": "/",
    "concurrents": RUDY_CONCURRENTS,
    "interval": RUDY_INTERVAL,
    "payload_size": RUDY_PAYLOAD,
    "method": "POST",
    "headers": [
        "Host: tempesta-tech.com",
        "Content-Type: application/x-www-form-urlencoded",
    ],
    "duration": RUDY_DURATION,
}

NGINX_CONFIG = """
pid ${pid};
worker_processes  auto;
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
    access_log off;

    server {
        listen 8000;

        location / {
            return 200 'ok';
        }

        location /nginx_status {
            stub_status on;
        }
    }
}
"""

BODY_TIMEOUT_WARNING = "Warning: frang: client body timeout exceeded"


class TestSlowHttpDDoS(tester.TempestaTest):
    """Verify Tempesta FW resilience under a RUDY slow-HTTP attack (HTTP/1 and HTTP/2)."""

    clients = [
        {
            **RUDY_COMMON,
            "id": "rudy-http1",
            "addr": "${tempesta_ip}:80",
            "ssl": False,
            "protocol": "http1",
            "insecure": False,
        },
        {
            **RUDY_COMMON,
            "id": "rudy-http2",
            "addr": "${tempesta_ip}:443",
            "ssl": True,
            "protocol": "http2",
            # Self-signed tempesta.crt in the lab.
            "insecure": True,
        },
        {
            "id": "curl-http1",
            "type": "curl",
            "http2": False,
            "ssl": False,
            "addr": "${tempesta_ip}",
        },
        {
            "id": "curl-http2",
            "type": "curl",
            "http2": True,
            "ssl": True,
            "addr": "${tempesta_ip}:443",
        },
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
    client_body_timeout {CLIENT_BODY_TIMEOUT};
    client_header_timeout 10;
    concurrent_tcp_connections {max(RUDY_CONCURRENTS * 2, 100)};
    http_strict_host_checking false;
    http_methods get post head;
}}

block_action attack drop;
block_action error reply;

srv_group main {{server ${{server_ip}}:8000 conns_n=128;}}

vhost tempesta-tech.com {{proxy_pass main;}}

tls_certificate ${{tempesta_workdir}}/tempesta.crt;
tls_certificate_key ${{tempesta_workdir}}/tempesta.key;
tls_match_any_server_name;

http_chain {{
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

    async def _legit_get(self, curl_id: str, path: str = "/") -> None:
        curl = self.get_client(curl_id)
        curl.headers["Host"] = "tempesta-tech.com"
        curl.set_uri(path)
        curl.start()
        await self.wait_while_busy(curl)
        curl.stop()

    @marks.Parameterize.expand(
        [
            marks.Param(name="http1", rudy_id="rudy-http1", curl_id="curl-http1"),
            marks.Param(name="http2", rudy_id="rudy-http2", curl_id="curl-http2"),
        ]
    )
    @dmesg.limited_rate_on_tempesta_node
    async def test_rudy_body_timeout_and_legit_traffic(self, name, rudy_id, curl_id):
        """
        RUDY opens many slow POSTs (1 byte every ``RUDY_INTERVAL``) over HTTP/1 or HTTP/2.

        Expectations:
        - frang ``client_body_timeout`` fires and logs body-timeout warnings;
        - legitimate GET traffic is still answered promptly during the attack.
        """
        klog = dmesg.DmesgFinder(disable_ratelimit=True)

        await self.start_all_services(client=False)

        # Baseline: legitimate client works before the attack.
        await self._legit_get(curl_id)
        curl = self.get_client(curl_id)
        self.assertEqual(curl.last_response.status, 200)

        rudy = self.get_client(rudy_id)
        rudy.start()

        # Let RUDY open connections and hit client_body_timeout at least once.
        await asyncio.sleep(CLIENT_BODY_TIMEOUT + 2)

        # Legitimate traffic must still succeed under the slow-POST flood.
        await self._legit_get(curl_id)
        self.assertEqual(
            curl.last_response.status,
            200,
            f"[{name}] Legitimate client did not get a response during the RUDY attack.",
        )
        total_time = (curl.last_stats or {}).get("time_total", RUDY_DURATION)
        self.assertLess(
            total_time,
            CLIENT_BODY_TIMEOUT,
            f"[{name}] Legitimate request was too slow under the RUDY attack "
            f"(time_total={total_time}).",
        )

        await rudy.wait_for_finish(timeout=RUDY_DURATION + 10)
        rudy.stop()

        # Frang must have observed incomplete slow bodies.
        found = await klog.find(
            BODY_TIMEOUT_WARNING,
            cond=dmesg.amount_greater_eq(1),
        )
        self.assertTrue(
            found,
            f"[{name}] Expected frang warnings '{BODY_TIMEOUT_WARNING}' during RUDY attack.",
        )

        # Service still healthy after the attack finishes.
        await self._legit_get(curl_id)
        self.assertEqual(curl.last_response.status, 200)

        tempesta = self.get_tempesta()
        tempesta.get_stats()
        self.assertGreaterEqual(
            tempesta.stats.cl_msg_received,
            3,
            f"[{name}] Tempesta FW did not receive client messages during the test.",
        )
