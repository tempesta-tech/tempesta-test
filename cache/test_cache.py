"""Functional tests of caching config."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"


from framework import tester
from framework.curl_client import CurlResponse
from framework.deproxy_client import DeproxyClient
from framework.deproxy_server import StaticDeproxyServer
from helpers import checks_for_tests as checks
from helpers import tf_cfg
from helpers.control import Tempesta

MIXED_CONFIG = (
    "cache {0};\r\n"
    + 'cache_fulfill suffix ".jpg" ".png";\r\n'
    + 'cache_bypass suffix ".avi";\r\n'
    + 'cache_bypass prefix "/static/dynamic_zone/";\r\n'
    + 'cache_fulfill prefix "/static/";\r\n'
)


class TestCache(tester.TempestaTest):
    """This class contains checks for tempesta cache config."""

    tempesta = {
        "config": """
listen 80;

server ${server_ip}:8000;

vhost default {
    proxy_pass default;
}
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

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    messages = 10

    def _test(self, uri: str, cache_mode: int, should_be_cached: bool, tempesta_config: str):
        """Update tempesta config. Send many identical requests and checks cache operation."""
        tempesta: Tempesta = self.get_tempesta()
        tempesta.config.defconfig += tempesta_config.format(cache_mode)

        self.start_all_services()

        srv: StaticDeproxyServer = self.get_server("deproxy")
        srv.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-Length: 13\r\n"
            + "Content-Type: text/html\r\n"
            + "\r\n"
            + "<html></html>\r\n",
        )

        client: DeproxyClient = self.get_client("deproxy")
        request = (
            f"GET {uri} HTTP/1.1\r\n"
            + "Host: {0}\r\n".format(tf_cfg.cfg.get("Client", "hostname"))
            + "Connection: keep-alive\r\n"
            + "Accept: */*\r\n"
            + "\r\n"
        )

        for _ in range(self.messages):
            client.send_request(request, expected_status_code="200")

        self.assertNotIn("age", client.responses[0].headers)
        msg = "Server has received unexpected number of requests."
        if should_be_cached:
            checks.check_tempesta_cache_stats(
                tempesta,
                cache_hits=self.messages - 1,
                cache_misses=1,
                cl_msg_served_from_cache=self.messages - 1,
            )
            self.assertEqual(len(srv.requests), 1, msg)
        else:
            checks.check_tempesta_cache_stats(
                tempesta,
                cache_hits=0,
                cache_misses=0,
                cl_msg_served_from_cache=0,
            )
            self.assertEqual(len(srv.requests), self.messages, msg)

        for response in client.responses[1:]:  # Note WPS 440
            if should_be_cached:
                self.assertIn("age", response.headers, msg)
            else:
                self.assertNotIn("age", response.headers, msg)

    def test_disabled_cache_fulfill_all(self):
        """If cache_mode = 0, responses has not received from cache. Other configs are ignored."""
        self._test(
            uri="/",
            cache_mode=0,
            should_be_cached=False,
            tempesta_config="cache {0};\r\ncache_fulfill * *;\r\n",
        )

    def test_sharding_cache_fulfill_all(self):
        """If cache_mode = 1 and cache_fulfill * *,  all requests are cached."""
        self._test(
            uri="/",
            cache_mode=1,
            should_be_cached=True,
            tempesta_config="cache {0};\r\ncache_fulfill * *;\r\n",
        )

    def test_replicated_cache_fulfill_all(self):
        """If cache_mode = 2 and cache_fulfill * *,  all requests are cached."""
        self._test(
            uri="/",
            cache_mode=2,
            should_be_cached=True,
            tempesta_config="cache {0};\r\ncache_fulfill * *;\r\n",
        )

    def test_disabled_cache_bypass_all(self):
        """If cache_mode = 0, responses has not received from cache. Other configs are ignored."""
        self._test(
            uri="/",
            cache_mode=0,
            should_be_cached=False,
            tempesta_config="cache {0};\r\ncache_bypass * *;\r\n",
        )

    def test_sharding_cache_bypass_all(self):
        """If cache_mode = 1 and cache_bypass * *,  all requests are not cached."""
        self._test(
            uri="/",
            cache_mode=1,
            should_be_cached=False,
            tempesta_config="cache {0};\r\ncache_bypass * *;\r\n",
        )

    def test_replicated_cache_bypass_all(self):
        """If cache_mode = 2 and cache_bypass * *, all requests are not cached."""
        self._test(
            uri="/",
            cache_mode=2,
            should_be_cached=False,
            tempesta_config="cache {0};\r\ncache_bypass * *;\r\n",
        )

    def test_disabled_cache_fulfill_suffix(self):
        """If cache_mode = 0, responses has not received from cache. Other configs are ignored."""
        self._test(
            uri="/picts/bear.jpg",
            cache_mode=0,
            should_be_cached=False,
            tempesta_config=MIXED_CONFIG,
        )

    def test_sharding_cache_fulfill_suffix(self):
        """If cache_mode = 1 and cache_fulfill suffix ".jpg", all requests are cached."""
        self._test(
            uri="/picts/bear.jpg",
            cache_mode=1,
            should_be_cached=True,
            tempesta_config=MIXED_CONFIG,
        )

    def test_replicated_cache_fulfill_suffix(self):
        """If cache_mode = 2 and cache_fulfill suffix ".jpg", all requests are cached."""
        self._test(
            uri="/picts/bear.jpg",
            cache_mode=2,
            should_be_cached=True,
            tempesta_config=MIXED_CONFIG,
        )

    def test_disabled_cache_fulfill_suffix2(self):
        """If cache_mode = 0, responses has not received from cache. Other configs are ignored."""
        self._test(
            uri="/jsnfsjk/jnd.png",
            cache_mode=0,
            should_be_cached=False,
            tempesta_config=MIXED_CONFIG,
        )

    def test_sharding_cache_fulfill_suffix2(self):
        """If cache_mode = 1 and cache_fulfill suffix ".png", all requests are cached."""
        self._test(
            uri="/jsnfsjk/jnd.png",
            cache_mode=1,
            should_be_cached=True,
            tempesta_config=MIXED_CONFIG,
        )

    def test_replicated_cache_fulfill_suffix2(self):
        """If cache_mode = 2 and cache_fulfill suffix ".png", all requests are cached."""
        self._test(
            uri="/jsnfsjk/jnd.png",
            cache_mode=2,
            should_be_cached=True,
            tempesta_config=MIXED_CONFIG,
        )

    def test_disabled_cache_bypass_suffix(self):
        """If cache_mode = 0, responses has not received from cache. Other configs are ignored."""
        self._test(
            uri="/howto/film.avi",
            cache_mode=0,
            should_be_cached=False,
            tempesta_config=MIXED_CONFIG,
        )

    def test_sharding_cache_bypass_suffix(self):
        """If cache_mode = 1 and cache_bypass suffix ".avi", all requests are not cached."""
        self._test(
            uri="/howto/film.avi",
            cache_mode=1,
            should_be_cached=False,
            tempesta_config=MIXED_CONFIG,
        )

    def test_replicated_cache_bypass_suffix(self):
        """If cache_mode = 2 and cache_bypass suffix ".avi", all requests are not cached."""
        self._test(
            uri="/howto/film.avi",
            cache_mode=2,
            should_be_cached=False,
            tempesta_config=MIXED_CONFIG,
        )

    def test_disabled_cache_bypass_prefix(self):
        """If cache_mode = 0, responses has not received from cache. Other configs are ignored."""
        self._test(
            uri="/static/dynamic_zone/content.html",
            cache_mode=0,
            should_be_cached=False,
            tempesta_config=MIXED_CONFIG,
        )

    def test_sharding_cache_bypass_prefix(self):
        """
        If cache_mode = 1 and cache_bypass prefix "/static/dynamic_zone/", all requests are not
        cached.
        """
        self._test(
            uri="/static/dynamic_zone/content.html",
            cache_mode=1,
            should_be_cached=False,
            tempesta_config=MIXED_CONFIG,
        )

    def test_replicated_cache_bypass_prefix(self):
        """
        If cache_mode = 2 and cache_bypass prefix "/static/dynamic_zone/", all requests are not
        cached.
        """
        self._test(
            uri="/static/dynamic_zone/content.html",
            cache_mode=2,
            should_be_cached=False,
            tempesta_config=MIXED_CONFIG,
        )

    def test_disabled_cache_fulfill_prefix(self):
        """If cache_mode = 0, responses has not received from cache. Other configs are ignored."""
        self._test(
            uri="/static/content.html",
            cache_mode=0,
            should_be_cached=False,
            tempesta_config=MIXED_CONFIG,
        )

    def test_sharding_cache_fulfill_prefix(self):
        """If cache_mode = 1 and cache_fulfill prefix "/static/", all requests are cached."""
        self._test(
            uri="/static/content.html",
            cache_mode=1,
            should_be_cached=True,
            tempesta_config=MIXED_CONFIG,
        )

    def test_replicated_cache_fulfill_prefix(self):
        """If cache_mode = 2 and cache_fulfill prefix "/static/", all requests are cached."""
        self._test(
            uri="/static/content.html",
            cache_mode=2,
            should_be_cached=True,
            tempesta_config=MIXED_CONFIG,
        )

    def test_cache_date(self):
        """
        If server response doesn't have date header, it is added to cache response and server
        response.
        """
        self._test(
            uri="/static/content.html",
            cache_mode=2,
            should_be_cached=True,
            tempesta_config=MIXED_CONFIG,
        )
        client = self.get_client("deproxy")
        for response in client.responses:
            self.assertIn("date", response.headers)


class H2Cache(tester.TempestaTest):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        }
    ]

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        }
    ]

    tempesta = {
        "config": """
        cache 2;
        cache_fulfill eq /to-be-cached;

        listen 443 proto=h2;
        tls_match_any_server_name;

        srv_group default {
            server ${server_ip}:8000;
        }

        vhost tempesta-tech.com {
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            proxy_pass default;
        }

       """
    }

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.start_all_clients()
        self.assertTrue(self.wait_all_connections())

    def test(self):
        self.start_all()

        request = [
            (":authority", "tempesta-tech.com"),
            (":path", "/to-be-cached"),
            (":scheme", "https"),
            (":method", "GET"),
        ]
        requests = [request, request]

        client = self.get_client("deproxy")
        client.make_requests(requests)

        got_response = client.wait_for_response(timeout=5)

        self.assertTrue(got_response)

        # Only the first request should be forwarded to the backend.
        self.assertEqual(
            len(self.get_server("deproxy").requests),
            1,
            "The second request wasn't served from cache.",
        )


class TestChunkedResponse(tester.TempestaTest):

    backends = [
        {
            "id": "chunked",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "9\r\n"
                "test-data\r\n"
                "0\r\n"
                "\r\n"
            ),
        },
    ]

    tempesta = {
        "config": """
        listen 80;
        cache 1;
        cache_fulfill * *;
        server ${server_ip}:8000;
        """
    }

    clients = [
        {
            "id": "get",
            "type": "curl",
            "cmd_args": (
                # Disable HTTP decoding, chunked data should be compared
                " --raw"
                # Prevent hang on invalid response
                " --max-time 1"
            ),
        },
    ]

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections(1))

    def get_response(self, client) -> CurlResponse:
        client.start()
        self.wait_while_busy(client)
        client.stop()
        return client.last_response

    def test_cached_data_equal_to_original(self):
        """
        Cached data of the chunked response
        should be equal to the original data.
        (see Tempesta issue #1698)
        """
        self.start_all()
        srv = self.get_server("chunked")
        client = self.get_client("get")

        with self.subTest("Get non-cached response"):
            response = self.get_response(client)
            self.assertEqual(response.status, 200, response)
            self.assertNotIn("age", response.headers)
            original_data = response.stdout

        with self.subTest("Get cached response"):
            response = self.get_response(client)
            self.assertEqual(response.status, 200, response)
            cached_data = response.stdout
            # check that response is from the cache
            self.assertEqual(len(srv.requests), 1)
            self.assertIn("age", response.headers)

        self.assertEqual(cached_data, original_data)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
