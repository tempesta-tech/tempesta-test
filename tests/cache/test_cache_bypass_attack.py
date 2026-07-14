"""Cache bypass / CDN origin amplification attacks (escudo#441).

Attackers avoid flooding Tempesta with malformed requests (which produce many
error responses and are easy to spot). Instead they stress the **web cache**
and force **origin** traffic with valid GETs:

1. **URI query parameters** — each unique ``?cb=N`` is a distinct cache key
   (or always a miss), so every request is a miss and hits the origin /
   pollutes the cache.
2. **``Cache-Control: no-cache`` / ``Pragma: no-cache``** — bypass stored
   responses for the same URI so every request is forwarded upstream.

Detection: Tempesta ``/proc/tempesta/perfstat`` shows high cache misses and
origin forwards with almost no client parse/other errors. Escudo filtration
for CDN amplification & bypass (escudo#441) consumes the same metrics; the
helpers live in ``framework.helpers.checks_for_tests``.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework.deproxy.deproxy_message import HttpMessage
from framework.helpers import checks_for_tests as checks
from framework.services.tempesta import Tempesta
from framework.test_suite import marks, tester

# Enough traffic for stable ratios in the filtration heuristic.
REQUEST_COUNT = 40

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

CACHED_BODY = "<html>cache-bypass-target</html>"


@marks.parameterize_class(
    [
        {"name": "Http", "clients": [DEPROXY_CLIENT]},
        {"name": "H2", "clients": [DEPROXY_CLIENT_H2]},
    ]
)
class TestCacheBypassAttack(tester.TempestaTest):
    """Stress Tempesta cache with valid (200) bypass traffic, not error floods."""

    tempesta = {
        "config": """
listen 80;
listen 443 proto=h2;

server ${server_ip}:8000;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;

cache 2;
cache_fulfill * *;
cache_methods GET HEAD;
frang_limits {http_strict_host_checking false;}
""",
    }

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "",
        },
    ]

    def _set_cacheable_origin_response(self) -> None:
        server = self.get_server("deproxy")
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + f"Content-Length: {len(CACHED_BODY)}\r\n"
            + "Content-Type: text/html\r\n"
            + "Cache-Control: public, max-age=3600\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + "\r\n"
            + CACHED_BODY
        )

    async def _send_get(self, uri: str, headers: list) -> None:
        client = self.get_client("deproxy")
        await client.send_request(
            client.create_request(method="GET", uri=uri, headers=headers),
            expected_status_code="200",
        )

    def _assert_no_error_flood(self, tempesta: Tempesta) -> None:
        """Attack must stress cache/origin with valid traffic, not error responses."""
        tempesta.get_stats()
        self.assertEqual(
            tempesta.stats.cl_msg_parsing_errors,
            0,
            "Cache-bypass attack must not generate client parse errors.",
        )
        self.assertEqual(
            tempesta.stats.cl_msg_other_errors,
            0,
            "Cache-bypass attack must not generate client other errors.",
        )
        self.assertEqual(
            tempesta.stats.srv_msg_parsing_errors,
            0,
            "Cache-bypass attack must not generate server parse errors.",
        )
        # Client asserted 200 on every response; perfstat client errors stay zero.

    async def test_uri_query_parameter_bypass(self):
        """
        Unique query parameters force distinct cache keys / misses so almost
        every request hits the origin (CDN back-to-origin amplification style)
        while all responses remain 200.
        """
        self._set_cacheable_origin_response()
        await self.start_all_services()

        server = self.get_server("deproxy")
        tempesta = self.get_tempesta()

        for i in range(REQUEST_COUNT):
            # Unique cache-busting parameter — valid resource, different key.
            await self._send_get(
                uri=f"/static/index.html?cb={i}&utm_source=bypass",
                headers=[("host", "tempesta-tech.com")],
            )

        tempesta.get_stats()
        self.assertEqual(
            tempesta.stats.cache_misses,
            REQUEST_COUNT,
            "Each unique query string should be a cache miss.",
        )
        self.assertEqual(
            tempesta.stats.cache_hits,
            0,
            "Unique URI parameters must not be served as cache hits.",
        )
        self.assertEqual(
            tempesta.stats.cl_msg_forwarded,
            REQUEST_COUNT,
            "All unique-URI requests must be forwarded to the origin.",
        )
        self.assertEqual(
            len(server.requests),
            REQUEST_COUNT,
            "Origin must see one request per unique URI parameter.",
        )
        self._assert_no_error_flood(tempesta)

        signal = checks.assert_cdn_amplification_bypass_detected(
            tempesta, min_requests=REQUEST_COUNT
        )
        self.assertGreaterEqual(signal.miss_ratio, 0.8)
        self.assertGreaterEqual(signal.origin_forward_ratio, 0.8)

    async def test_no_cache_header_bypass(self):
        """
        Same URI with ``Cache-Control: no-cache`` (and ``Pragma``) forces origin
        revalidation / bypass so the attack does not rely on error responses.
        """
        self._set_cacheable_origin_response()
        await self.start_all_services()

        server = self.get_server("deproxy")
        tempesta = self.get_tempesta()
        uri = "/static/index.html"

        # Populate cache once without bypass headers.
        await self._send_get(uri=uri, headers=[("host", "tempesta-tech.com")])
        # Confirm a normal hit is possible (sanity for cache config).
        await self._send_get(uri=uri, headers=[("host", "tempesta-tech.com")])
        self.assertIn("age", self.get_client("deproxy").last_response.headers)

        # Bypass flood: same URI, no-cache request directives.
        for _ in range(REQUEST_COUNT):
            await self._send_get(
                uri=uri,
                headers=[
                    ("host", "tempesta-tech.com"),
                    ("cache-control", "no-cache"),
                    ("pragma", "no-cache"),
                ],
            )

        tempesta.get_stats()
        # At least the bypass requests must miss / be forwarded; total misses
        # include the first populate miss (and not the voluntary cache hit).
        self.assertGreaterEqual(
            tempesta.stats.cache_misses,
            REQUEST_COUNT,
            "no-cache requests must produce cache misses.",
        )
        self.assertGreaterEqual(
            tempesta.stats.cl_msg_forwarded,
            REQUEST_COUNT,
            "no-cache requests must be forwarded to the origin.",
        )
        # Origin saw: 1 populate + REQUEST_COUNT bypass (cache hit did not go origin).
        self.assertGreaterEqual(
            len(server.requests),
            1 + REQUEST_COUNT,
            "Origin must receive populate + no-cache bypass requests.",
        )
        self._assert_no_error_flood(tempesta)

        signal = checks.assert_cdn_amplification_bypass_detected(
            tempesta, min_requests=REQUEST_COUNT
        )
        self.assertGreaterEqual(signal.miss_ratio, 0.8)
        self.assertLessEqual(signal.error_ratio, 0.05)

    async def test_combined_uri_params_and_no_cache(self):
        """
        Combined technique: unique query strings **and** no-cache headers.
        Maximises origin load and cache pressure without error responses.
        """
        self._set_cacheable_origin_response()
        await self.start_all_services()

        server = self.get_server("deproxy")
        tempesta = self.get_tempesta()

        for i in range(REQUEST_COUNT):
            await self._send_get(
                uri=f"/api/resource?id={i}&v={i * 7}",
                headers=[
                    ("host", "tempesta-tech.com"),
                    ("cache-control", "no-cache"),
                    ("pragma", "no-cache"),
                ],
            )

        tempesta.get_stats()
        self.assertEqual(tempesta.stats.cache_misses, REQUEST_COUNT)
        self.assertEqual(tempesta.stats.cache_hits, 0)
        self.assertEqual(tempesta.stats.cl_msg_forwarded, REQUEST_COUNT)
        self.assertEqual(tempesta.stats.cl_msg_served_from_cache, 0)
        self.assertEqual(len(server.requests), REQUEST_COUNT)
        self._assert_no_error_flood(tempesta)

        signal = checks.assert_cdn_amplification_bypass_detected(
            tempesta, min_requests=REQUEST_COUNT
        )
        self.assertTrue(signal.detected)
        self.assertEqual(signal.error_ratio, 0.0)
        self.assertEqual(signal.miss_ratio, 1.0)
