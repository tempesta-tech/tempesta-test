"""Functional tests of caching config."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import time
from http import HTTPStatus

from framework.curl_client import CurlResponse
from framework.deproxy_server import StaticDeproxyServer
from helpers import deproxy
from helpers.control import Tempesta
from helpers.deproxy import HttpMessage
from test_suite import checks_for_tests as checks
from test_suite import tester
from test_suite.parameterize import param, parameterize, parameterize_class

MIXED_CONFIG = (
    "cache {0};\r\n"
    + 'cache_fulfill suffix ".jpg" ".png";\r\n'
    + 'cache_bypass suffix ".avi";\r\n'
    + 'cache_bypass prefix "/static/dynamic_zone/";\r\n'
    + 'cache_fulfill prefix "/static/";\r\n'
)

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

DEPROXY_SERVER = {
    "id": "deproxy",
    "type": "deproxy",
    "port": "8000",
    "response": "static",
    "response_content": "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n",
}


@parameterize_class(
    [
        {"name": "Http", "clients": [DEPROXY_CLIENT]},
        {"name": "H2", "clients": [DEPROXY_CLIENT_H2]},
    ]
)
class TestCache(tester.TempestaTest):
    """This class contains checks for tempesta cache config."""

    tempesta = {
        "config": """
listen 80;
listen 443 proto=h2;

server ${server_ip}:8000;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
""",
    }

    backends = [DEPROXY_SERVER]

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
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + "\r\n"
            + "<html></html>"
        )

        client = self.get_client("deproxy")
        request = client.create_request(
            method="GET",
            uri=uri,
            headers=[
                ("connection", "keep-alive"),
            ],
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


@parameterize_class(
    [
        {"name": "Http", "clients": [DEPROXY_CLIENT]},
        {"name": "H2", "clients": [DEPROXY_CLIENT_H2]},
    ]
)
class TestCacheDublicateHeaders(tester.TempestaTest):
    tempesta = {
        "config": """
listen 80;
listen 443 proto=h2;
cache 2;
cache_fulfill * *;

server ${server_ip}:8000;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
""",
    }

    backends = [DEPROXY_SERVER]

    @parameterize.expand(
        [
            param(name="raw", header_name="hdr", val1="aaa", val2="bbb"),
            param(
                name="regular",
                header_name="set-cookie",
                val1="aaa=bbb",
                val2="ccc=ddd",
            ),
        ]
    )
    def test(self, name, header_name, val1, val2):
        tempesta: Tempesta = self.get_tempesta()
        self.start_all_services()

        srv: StaticDeproxyServer = self.get_server("deproxy")
        srv.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-Length: 13\r\n"
            + "Content-Type: text/html\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + f"{header_name}: {val1}\r\n"
            + f"{header_name}: {val2}\r\n"
            + "\r\n"
            + "<html></html>"
        )

        client = self.get_client("deproxy")
        request = client.create_request(
            method="GET",
            uri="/",
            headers=[
                ("connection", "keep-alive"),
            ],
        )

        for _ in range(0, 2):
            client.send_request(request, expected_status_code="200")

        self.assertNotIn("age", client.responses[0].headers)
        self.assertIn("age", client.responses[1].headers)
        for resp in client.responses:
            h_values = tuple(resp.headers.find_all(header_name))
            self.assertEqual(h_values, (val1, val2))

        msg = "Server has received unexpected number of requests."
        checks.check_tempesta_cache_stats(
            tempesta,
            cache_hits=1,
            cache_misses=1,
            cl_msg_served_from_cache=1,
        )
        self.assertEqual(len(srv.requests), 1, msg)


@parameterize_class(
    [
        {"name": "Http", "clients": [DEPROXY_CLIENT]},
        {"name": "H2", "clients": [DEPROXY_CLIENT_H2]},
    ]
)
class TestQueryParamsAndRedirect(tester.TempestaTest):
    tempesta = {
        "config": """
listen 80;
listen 443 proto=h2;
cache 2;
cache_fulfill * *;

server ${server_ip}:8000;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
""",
    }

    backends = [DEPROXY_SERVER]

    @parameterize.expand(
        [
            param(
                name="different_key",
                uri_1="/pic.jpg?param1=value1",
                uri_2="/pic.jpg?param2=value1",
                should_be_cached=False,
            ),
            param(
                name="different_value",
                uri_1="/pic.jpg?param1=value1",
                uri_2="/pic.jpg?param1=value2",
                should_be_cached=False,
            ),
            param(
                name="with_new_param",
                uri_1="/pic.jpg?param1=value1",
                uri_2="/pic.jpg?param1=value1&param2=value2",
                should_be_cached=False,
            ),
            param(
                name="with_new_param",
                uri_1="/pic.jpg?param1=value1",
                uri_2="/pic.jpg?param1=value1&param1=value1",
                should_be_cached=False,
            ),
            param(
                name="same_params",
                uri_1="/pic.jpg?param1=value1",
                uri_2="/pic.jpg?param1=value1",
                should_be_cached=True,
            ),
        ]
    )
    def test_query_param(self, name, uri_1, uri_2, should_be_cached):
        self.start_all_services()

        server = self.get_server("deproxy")
        client = self.get_client("deproxy")

        for uri in [uri_1, uri_2]:
            client.send_request(
                client.create_request(method="GET", uri=uri, headers=[]),
                expected_status_code="200",
            )

        if should_be_cached:
            self.assertIn("age", client.last_response.headers)

            checks.check_tempesta_cache_stats(
                self.get_tempesta(),
                cache_hits=1,
                cache_misses=1,
                cl_msg_served_from_cache=1,
            )
            self.assertEqual(len(server.requests), 1)
        else:
            self.assertNotIn("age", client.last_response.headers)

            checks.check_tempesta_cache_stats(
                self.get_tempesta(),
                cache_hits=0,
                cache_misses=2,
                cl_msg_served_from_cache=0,
            )
            self.assertEqual(len(server.requests), 2)

    @parameterize.expand(
        [
            param(
                name="300_multiple_choices",
                response=HTTPStatus.MULTIPLE_CHOICES,
                should_be_cached=True,
            ),
            param(
                name="301_moved_permanently",
                response=HTTPStatus.MOVED_PERMANENTLY,
                should_be_cached=True,
            ),
            param(
                name="302_found",
                response=HTTPStatus.FOUND,
                should_be_cached=False,
            ),
            param(
                name="303_see_other",
                response=HTTPStatus.SEE_OTHER,
                should_be_cached=False,
            ),
            param(
                name="304_not_modified",
                response=HTTPStatus.NOT_MODIFIED,
                should_be_cached=False,
            ),
            param(
                name="305_user_proxy",
                response=HTTPStatus.USE_PROXY,
                should_be_cached=False,
            ),
            param(
                name="307_temporary_redirect",
                response=HTTPStatus.TEMPORARY_REDIRECT,
                should_be_cached=False,
            ),
            param(
                name="308_permanent_redirect",
                response=HTTPStatus.PERMANENT_REDIRECT,
                should_be_cached=True,
            ),
        ]
    )
    def test_redirect(self, name, response, should_be_cached):
        server = self.get_server("deproxy")
        client = self.get_client("deproxy")

        server.set_response(
            f"HTTP/1.1 {response.value} {response.phrase}\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-Length: 0\r\n"
            + "Location: http://www.example.com/index.html\r\n"
            + "\r\n"
        )

        self.start_all_services()

        for _ in range(2):
            client.send_request(
                client.create_request(method="GET", uri="/index.html", headers=[]),
                expected_status_code=str(response.value),
            )

        if should_be_cached:
            # self.assertIn("age", client.last_response.headers)
            checks.check_tempesta_cache_stats(
                self.get_tempesta(),
                cache_hits=1,
                cache_misses=1,
                cl_msg_served_from_cache=1,
            )
            self.assertEqual(len(server.requests), 1)
        else:
            self.assertNotIn("age", client.last_response.headers)
            checks.check_tempesta_cache_stats(
                self.get_tempesta(),
                cache_hits=0,
                cache_misses=2,
                cl_msg_served_from_cache=0,
            )
            self.assertEqual(len(server.requests), 2)


@parameterize_class(
    [
        {"name": "Http", "clients": [DEPROXY_CLIENT]},
        {"name": "H2", "clients": [DEPROXY_CLIENT_H2]},
    ]
)
class TestCacheLocation(tester.TempestaTest):
    tempesta = {
        "config": """
listen 80;
listen 443 proto=h2;
server ${server_ip}:8000;
cache 2;

tls_match_any_server_name;
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;

vhost default {
    proxy_pass default;
    
    location suffix ".jpg" {
        proxy_pass default;
        cache_fulfill * *;
    }

    location prefix "/bypassed" {
        proxy_pass default;
        cache_bypass * *;
    }

    location prefix "/nonidempotent" {
        proxy_pass default;
        cache_fulfill * *;
        nonidempotent GET * *;
        nonidempotent HEAD * *;
        nonidempotent POST * *;
    }
}
""",
    }

    backends = [DEPROXY_SERVER]

    def _test(self, uri: str, method: str, should_be_cached: bool):
        self.start_all_services()

        srv: StaticDeproxyServer = self.get_server("deproxy")
        client = self.get_client("deproxy")
        request = client.create_request(uri=uri, method=method, headers=[])

        for _ in range(2):
            client.send_request(request, expected_status_code="200")

        self.assertNotIn("age", client.responses[0].headers)
        msg = "Server has received unexpected number of requests."

        self.assertEqual(len(srv.requests), 1 if should_be_cached else 2, msg)

        if should_be_cached:
            self.assertIn("age", client.last_response.headers, msg)
        else:
            self.assertNotIn("age", client.last_response.headers, msg)

    def test_suffix_cached(self):
        self._test(uri="/image.jpg", method="GET", should_be_cached=True)

    def test_prefix_bypassed(self):
        self._test(uri="/bypassed", method="GET", should_be_cached=False)

    def test_nonidempotent_get(self):
        self._test(uri="/nonidempotent", method="GET", should_be_cached=False)

    def test_nonidempotent_head(self):
        self._test(uri="/nonidempotent", method="HEAD", should_be_cached=False)

    def test_suffix_cached_and_prefix_bypassed(self):
        """
        Wiki:
            Multiple virtual hosts and locations may be defined and are processed
            strictly in the order they are defined in the configuration file.
        https://github.com/tempesta-tech/tempesta/wiki/Virtual-hosts-and-locations
        Response must be cached because location with suffix `.jpg` is first.
        """
        self._test(uri="/bypassed/image.jpg", method="GET", should_be_cached=True)


@parameterize_class(
    [
        {"name": "Http", "clients": [DEPROXY_CLIENT]},
        {"name": "H2", "clients": [DEPROXY_CLIENT_H2]},
    ]
)
class TestCacheMultipleMethods(tester.TempestaTest):
    backends = [DEPROXY_SERVER]

    tempesta = {
        "config": """
    listen 80;
    listen 443 proto=h2;
    cache 2;
    cache_fulfill * *;
    cache_methods GET HEAD POST;
    frang_limits {http_methods GET HEAD POST PUT DELETE;}

    server ${server_ip}:8000;

    tls_match_any_server_name;
    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;
    """,
    }

    @parameterize.expand(
        [
            param("GET_after_GET", first_method="GET", second_method="GET", should_be_cached=True),
            param(
                "HEAD_after_GET", first_method="GET", second_method="HEAD", should_be_cached=True
            ),
            param(
                "POST_after_GET", first_method="GET", second_method="POST", should_be_cached=False
            ),
            param(
                "HEAD_after_HEAD", first_method="HEAD", second_method="HEAD", should_be_cached=True
            ),
            param(
                "GET_after_HEAD", first_method="HEAD", second_method="GET", should_be_cached=False
            ),
            param(
                "POST_after_HEAD", first_method="HEAD", second_method="POST", should_be_cached=False
            ),
        ]
    )
    def test(self, name, first_method, second_method, should_be_cached):
        """
        The response to a GET request is cacheable; a cache MAY use it to
        satisfy subsequent GET and HEAD requests.
        RFC 9110 9.3.1

        The response to a HEAD request is cacheable; a cache MAY use it to
        satisfy subsequent HEAD requests
        RFC 9110 9.3.2
        """
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-Length: 5\r\n"
            + "\r\n"
            + "12345"
        )

        self.start_all_services()
        client.send_request(
            client.create_request(method=first_method, uri="/index.html", headers=[]), "200"
        )
        client.send_request(
            client.create_request(method=second_method, uri="/index.html", headers=[]), "200"
        )

        if should_be_cached:
            self.assertIn("age", client.last_response.headers.keys())
            self.assertEqual(len(server.requests), 1)
        else:
            self.assertNotIn("age", client.last_response.headers.keys())
            self.assertEqual(len(server.requests), 2)

    @parameterize.expand(
        [
            param(name="PUT_request", method="PUT"),
            param(name="DELETE_request", method="DELETE"),
        ]
    )
    def test_update_cache_via(self, name, method):
        """
        Responses to the PUT/DELETE method are not cacheable.
        If a successful PUT request passes through a cache that has one or more stored
        responses for the target URI, those stored responses will be invalidated.
        RFC 9110 9.3.4/9.3.5

        "Invalidate" means that the cache will either remove all stored responses whose
        target URI matches the given URI or mark them as "invalid" and in need of a mandatory
        validation before they can be sent in response to a subsequent request.
        RFC 9111 4.4
        """
        server = self.get_server("deproxy")
        client = self.get_client("deproxy")

        self.start_all_services()

        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-Length: 11\r\n"
            + "\r\n"
            + "First body."
        )
        client.send_request(
            client.create_request(method="GET", uri="/index.html", headers=[]), "200"
        )

        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-Length: 12\r\n"
            + "\r\n"
            + "Second body."
        )
        client.send_request(
            client.create_request(method=method, uri="/index.html", headers=[]), "200"
        )
        client.send_request(
            client.create_request(method="GET", uri="/index.html", headers=[]), "200"
        )

        self.assertEqual(
            "Second body.",
            client.last_response.body,
            f"The response was not updated in the cache after a request with {method} method.",
        )

    @parameterize.expand(
        [
            param(name="GET", second_method="GET", should_be_cached=True),
            param(name="HEAD", second_method="HEAD", should_be_cached=True),
            param(name="POST", second_method="POST", should_be_cached=False),
        ]
    )
    def test_cache_POST_request_with_location(self, name, second_method, should_be_cached):
        """
        Responses to POST requests are only cacheable when they include explicit
        freshness information and a Content-Location header field that has the same
        value as the POST's target URI. A cached POST response can be reused to satisfy
        a later GET or HEAD request. In contrast, a POST request cannot be satisfied by
        a cached POST response because POST is potentially unsafe.
        RFC 9110 9.3.3
        """
        server = self.get_server("deproxy")
        client = self.get_client("deproxy")

        self.start_all_services()

        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-Length: 11\r\n"
            + "Content-Location: /index.html\r\n"
            + "Cache-Control: public, s-maxage=5\r\n"
            + "\r\n"
            + "First body."
        )

        client.send_request(
            client.create_request(method="POST", uri="/index.html", headers=[]), "200"
        )
        client.send_request(
            client.create_request(method=second_method, uri="/index.html", headers=[]), "200"
        )

        if should_be_cached:
            self.assertIn("age", client.last_response.headers.keys())
            self.assertEqual(len(server.requests), 1)
        else:
            self.assertNotIn("age", client.last_response.headers.keys())
            self.assertEqual(len(server.requests), 2)

    @parameterize.expand(
        [
            param(
                name="not_same_location",
                extra_header="Content-Location: /index1.html\r\n"
                + "Cache-Control: public, s-maxage=5\r\n",
            ),
            param(name="no_cache_control", extra_header="Content-Location: /index.html\r\n"),
        ]
    )
    def test_cache_POST_request_not_cached(self, name, extra_header):
        """
        Responses to POST requests are only cacheable when they include explicit freshness
        information and a Content-Location header field that has the same value as the POST's
        target URI.
        """
        server = self.get_server("deproxy")
        client = self.get_client("deproxy")

        self.start_all_services()

        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-Length: 0\r\n"
            + extra_header
            + "\r\n"
        )

        client.send_request(
            client.create_request(method="POST", uri="/index.html", headers=[]), "200"
        )
        client.send_request(
            client.create_request(method="GET", uri="/index.html", headers=[]), "200"
        )
        self.assertNotIn("age", client.last_response.headers.keys())
        self.assertEqual(len(server.requests), 2)

    @parameterize.expand(
        [
            param(
                name="GET_POST",
                first_method="GET",
                second_method="POST",
                second_headers=[],
                sleep_interval=0,
            ),
            param(
                name="GET_GET",
                first_method="GET",
                second_method="GET",
                second_headers=[("cache-control", "max-age=1")],
                sleep_interval=2,
            ),
            param(
                name="GET_HEAD",
                first_method="GET",
                second_method="HEAD",
                second_headers=[("cache-control", "max-age=1")],
                sleep_interval=2,
            ),
            param(
                name="POST_POST",
                first_method="POST",
                second_method="POST",
                second_headers=[],
                sleep_interval=0,
            ),
            param(
                name="POST_GET",
                first_method="POST",
                second_method="GET",
                second_headers=[("cache-control", "max-age=1")],
                sleep_interval=2,
            ),
            param(
                name="POST_HEAD",
                first_method="POST",
                second_method="HEAD",
                second_headers=[("cache-control", "max-age=1")],
                sleep_interval=2,
            ),
        ]
    )
    def test_several_entries(
        self, name, first_method, second_method, second_headers, sleep_interval
    ):
        """
        Tempesta can save several entries in cache and use more appropriate
        entry to satisfy the next request.
        """
        server = self.get_server("deproxy")
        client = self.get_client("deproxy")

        self.start_all_services()
        if second_method == "HEAD":
            self.disable_deproxy_auto_parser()

        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-Length: 11\r\n"
            + "Content-Location: /index.html\r\n"
            + "Cache-Control: public, s-maxage=5\r\n"
            + "\r\n"
            + "First body."
        )

        # Send first request. Tempesta FW forward request to backend server and
        # save response in cache.
        client.send_request(
            client.create_request(method=first_method, uri="/index.html", headers=[]),
            expected_status_code="200",
        )
        self.assertNotIn("age", client.last_response.headers.keys())
        self.assertEqual(len(server.requests), 1)
        self.assertEqual("First body.", client.last_response.body)

        # Sleep to be shure that second request will be sent to
        # backend server, because of cache-control header.
        time.sleep(sleep_interval)

        second_response = (
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + ("Content-Length: %d\r\n" % (12 if second_method != "HEAD" else 0))
            + "Content-Location: /index.html\r\n"
            + "Cache-Control: public, s-maxage=5\r\n"
            + "\r\n"
        )

        if second_method != "HEAD":
            second_response += "Second body."

        server.set_response(second_response)

        # Send second request. Tempesta FW forward request to backend server and
        # save response in cache (for some requests we use cache-control directive
        # to be shure that request will be forwarded to backend server). There
        # are two cache enries now in Tempesta FW cache.
        client.send_request(
            client.create_request(method=second_method, uri="/index.html", headers=second_headers),
            expected_status_code="200",
        )
        self.assertNotIn("age", client.last_response.headers.keys())
        self.assertEqual(len(server.requests), 2)
        self.assertEqual(
            "Second body." if second_method != "HEAD" else "", client.last_response.body
        )

        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-Length: 11\r\n"
            + "Content-Location: /index.html\r\n"
            + "Cache-Control: public, s-maxage=5\r\n"
            + "\r\n"
            + "Third body."
        )

        # Send third GET request, which can be satisfied from cache.
        client.send_request(
            client.create_request(method="GET", uri="/index.html", headers=[]),
            expected_status_code="200",
        )
        self.assertIn("age", client.last_response.headers.keys())
        self.assertEqual(len(server.requests), 2)
        # Tempesta FW satisfy request from cache, using the most appropriate
        # entry. When second request has GET or POST method, Tempesta FW uses
        # it to satisfy third request, because it is the freshest cache entry.
        # If second request has HEAD method, we can't use it response to satisfy
        # GET request, so use first entry.
        self.assertEqual(
            "Second body." if second_method != "HEAD" else "First body.", client.last_response.body
        )


class TestH2CacheHdrDel(tester.TempestaTest):
    clients = [DEPROXY_CLIENT_H2]

    backends = [DEPROXY_SERVER]

    tempesta = {
        "config": """
listen 80;
listen 443 proto=h2;

server ${server_ip}:8000;

tls_match_any_server_name;
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
cache 2;
"""
    }

    def base_scenario(
        self,
        tempesta_config: str,
        response_headers: list,
        expected_cached_headers: list,
        should_be_cached: bool,
    ):
        tempesta = self.get_tempesta()
        tempesta.config.defconfig += tempesta_config
        self.disable_deproxy_auto_parser()

        self.start_all_services()

        response = deproxy.Response.create(
            status="200",
            headers=response_headers + [("content-length", "0")],
            date=deproxy.HttpMessage.date_time_string(),
        )
        expected_response = deproxy.H2Response.create(
            status=response.status,
            headers=response.headers.headers,
            date=response.headers.get("date"),
            tempesta_headers=True,
            expected=True,
        )

        server = self.get_server("deproxy")
        server.set_response(response)

        client = self.get_client("deproxy")
        request = client.create_request(method="GET", headers=[], uri="/")
        client.send_request(request, "200")
        self.assertEqual(client.last_response, expected_response)

        client.send_request(request, "200")
        if should_be_cached:
            optional_headers = [("content-length", "0"), ("age", "0")]
        else:
            optional_headers = [("content-length", "0")]
        expected_cached_response = deproxy.H2Response.create(
            status=response.status,
            headers=expected_cached_headers + optional_headers,
            date=response.headers.get("date"),
            tempesta_headers=True,
            expected=True,
        )

        self.assertEqual(client.last_response, expected_cached_response)
        self.assertEqual(len(server.requests), 1 if should_be_cached else 2)

    # cache_resp_hdr_del --------------------------------------------------------------------------
    def test_cache_bypass_and_hdr_del(self):
        self.base_scenario(
            tempesta_config="cache_bypass * *;\ncache_resp_hdr_del set-cookie remove-me-2;\n",
            response_headers=[("set-cookie", "cookie=2; a=b"), ("remove-me-2", "")],
            expected_cached_headers=[("set-cookie", "cookie=2; a=b"), ("remove-me-2", "")],
            should_be_cached=False,
        )

    def test_cache_fulfill_and_hdr_del(self):
        self.base_scenario(
            tempesta_config="cache_fulfill * *;\ncache_resp_hdr_del set-cookie remove-me-2;\n",
            response_headers=[("set-cookie", "cookie=2; a=b"), ("remove-me-2", "")],
            expected_cached_headers=[],
            should_be_cached=True,
        )

    def test_cache_bypass(self):
        """
        This test does a regular caching without additional processing,
        however, the regular caching might not work correctly for
        empty 'Remove-me' header value due to a bug in message fixups. See #530.
        """
        self.base_scenario(
            tempesta_config="cache_bypass * *;\n",
            response_headers=[("remove-me", ""), ("remove-me-2", "")],
            expected_cached_headers=[("remove-me", ""), ("remove-me-2", "")],
            should_be_cached=False,
        )

    def test_cache_fulfill(self):
        """
        This test does a regular caching without additional processing,
        however, the regular caching might not work correctly for
        empty 'Remove-me' header value due to a bug in message fixups. See #530.
        """
        self.base_scenario(
            tempesta_config="cache_fulfill * *;\n",
            response_headers=[("remove-me", ""), ("remove-me-2", "")],
            expected_cached_headers=[("remove-me", ""), ("remove-me-2", "")],
            should_be_cached=True,
        )

    # NO-CACHE ------------------------------------------------------------------------------------
    def test_cache_bypass_no_cache_with_arg(self):
        """Tempesta must not change response if cache_bypass is present."""
        self.base_scenario(
            tempesta_config="cache_bypass * *;\n",
            response_headers=[
                ("remove-me", "a"),
                ("remove-me-2", "a"),
                ("cache-control", 'no-cache="remove-me"'),
            ],
            expected_cached_headers=[
                ("remove-me", "a"),
                ("remove-me-2", "a"),
                ("cache-control", 'no-cache="remove-me"'),
            ],
            should_be_cached=False,
        )

    def test_cache_fulfilll_no_cache_with_arg(self):
        """
        Tempesta must not save remove-me header in cache
        if cache-control no-cache="remove-me".
        """
        self.base_scenario(
            tempesta_config="cache_fulfill * *;\n",
            response_headers=[
                ("remove-me", ""),
                ("remove-me-2", ""),
                ("cache-control", 'no-cache="remove-me"'),
            ],
            expected_cached_headers=[
                ("remove-me-2", ""),
                ("cache-control", 'no-cache="remove-me"'),
            ],
            should_be_cached=True,
        )

    def test_cache_fulfilll_no_cache_with_arg_2(self):
        """
        Tempesta must not save remove-me header in cache
        if cache-control no-cache="remove-me".
        """
        self.base_scenario(
            tempesta_config="cache_fulfill * *;\n",
            response_headers=[
                ("remove-me", "a"),
                ("remove-me-2", '"a"'),
                ("cache-control", 'no-cache="remove-me"'),
            ],
            expected_cached_headers=[
                ("remove-me-2", '"a"'),
                ("cache-control", 'no-cache="remove-me"'),
            ],
            should_be_cached=True,
        )

    def test_cache_fulfilll_no_cache_with_args(self):
        """Tempesta must not save all headers from no-cache."""
        self.base_scenario(
            tempesta_config="cache_fulfill * *;\n",
            response_headers=[
                ("remove-me", "a"),
                ("remove-me-2", '"a"'),
                ("cache-control", 'no-cache="remove-me, remove-me-2"'),
            ],
            expected_cached_headers=[("cache-control", 'no-cache="remove-me, remove-me-2"')],
            should_be_cached=True,
        )

    def test_cache_fulfilll_multi_cache_control(self):
        """Tempesta must not save all headers from no-cache."""
        self.base_scenario(
            tempesta_config="cache_fulfill * *;\n",
            response_headers=[
                ("remove-me", "a"),
                ("remove-me-2", '"a"'),
                ("cache-control", 'public, no-cache="remove-me", max-age=100, must-revalidate'),
            ],
            expected_cached_headers=[
                ("remove-me-2", '"a"'),
                ("cache-control", 'public, no-cache="remove-me", max-age=100, must-revalidate'),
            ],
            should_be_cached=True,
        )

    # PRIVATE -------------------------------------------------------------------------------------
    def test_cache_bypass_private_with_arg(self):
        """Tempesta must not change response if cache_bypass is present."""
        self.base_scenario(
            tempesta_config="cache_bypass * *;\n",
            response_headers=[
                ("remove-me", "a"),
                ("remove-me-2", "a"),
                ("cache-control", 'private="remove-me"'),
            ],
            expected_cached_headers=[
                ("remove-me", "a"),
                ("remove-me-2", "a"),
                ("cache-control", 'private="remove-me"'),
            ],
            should_be_cached=False,
        )

    def test_cache_fulfilll_private_with_arg(self):
        """
        Tempesta must not save remove-me header in cache
        if cache-control private="remove-me".
        """
        self.base_scenario(
            tempesta_config="cache_fulfill * *;\n",
            response_headers=[
                ("remove-me", ""),
                ("remove-me-2", ""),
                ("cache-control", 'private="remove-me"'),
            ],
            expected_cached_headers=[("remove-me-2", ""), ("cache-control", 'private="remove-me"')],
            should_be_cached=True,
        )

    def test_cache_fulfilll_private_with_arg_2(self):
        """
        Tempesta must not save remove-me header in cache
        if cache-control private="remove-me".
        """
        self.base_scenario(
            tempesta_config="cache_fulfill * *;\n",
            response_headers=[
                ("remove-me", "a"),
                ("remove-me-2", '"a"'),
                ("cache-control", 'private="remove-me"'),
            ],
            expected_cached_headers=[
                ("remove-me-2", '"a"'),
                ("cache-control", 'private="remove-me"'),
            ],
            should_be_cached=True,
        )

    def test_cache_fulfilll_private_with_args(self):
        """Tempesta must not save all headers from no-cache."""
        self.base_scenario(
            tempesta_config="cache_fulfill * *;\n",
            response_headers=[
                ("remove-me", "a"),
                ("remove-me-2", '"a"'),
                ("cache-control", 'private="remove-me, remove-me-2"'),
            ],
            expected_cached_headers=[("cache-control", 'private="remove-me, remove-me-2"')],
            should_be_cached=True,
        )

    def test_cache_fulfilll_multi_cache_control_2(self):
        """Tempesta must not save all headers from no-cache."""
        self.base_scenario(
            tempesta_config="cache_fulfill * *;\n",
            response_headers=[
                ("remove-me", "a"),
                ("remove-me-2", '"a"'),
                ("cache-control", 'public, private="remove-me", max-age=100, must-revalidate'),
            ],
            expected_cached_headers=[
                ("remove-me-2", '"a"'),
                ("cache-control", 'public, private="remove-me", max-age=100, must-revalidate'),
            ],
            should_be_cached=True,
        )


class TestH2CacheTtl(tester.TempestaTest):
    tempesta = {
        "config": """
listen 80;
listen 443 proto=h2;

tls_match_any_server_name;
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;

server ${server_ip}:8000;
frang_limits {http_strict_host_checking false;}
vhost vh1 {
    proxy_pass default;
}

cache 2;
cache_fulfill * *;
cache_ttl 3;

http_chain {
    cookie "comment_author_*" == "*" -> cache_ttl = 1;
    -> vh1;
}
"""
    }

    clients = [DEPROXY_CLIENT_H2]

    backends = [DEPROXY_SERVER]

    def base_scenario(
        self,
        response_headers: list,
        request_headers: list,
        second_request_headers: list,
        sleep_interval: float,
        should_be_cached: bool,
    ):
        self.start_all_services()

        server = self.get_server("deproxy")
        server.set_response(
            deproxy.Response.create(
                status="200",
                headers=response_headers + [("content-length", "0")],
                date=deproxy.HttpMessage.date_time_string(),
            )
        )

        client = self.get_client("deproxy")
        client.send_request(
            client.create_request(method="GET", headers=request_headers, uri="/"),
            "200",
        )

        time.sleep(sleep_interval)

        server.set_response(
            deproxy.Response.create(
                status="200",
                headers=response_headers + [("content-length", "0")],
                date=deproxy.HttpMessage.date_time_string(),
            )
        )
        client.send_request(
            client.create_request(method="GET", headers=second_request_headers, uri="/"),
            "200",
        )

        self.assertEqual(1 if should_be_cached else 2, len(server.requests))

    def test_global_cache_ttl_3_sleep_0(self):
        """Response must be from cache if sleep < cache_ttl."""
        self.base_scenario(
            response_headers=[],
            request_headers=[],
            second_request_headers=[],
            sleep_interval=0,
            should_be_cached=True,
        )

    def test_global_cache_ttl_3_sleep_4(self):
        """Response must not be from cache if sleep > cache_ttl."""
        self.base_scenario(
            response_headers=[],
            request_headers=[],
            second_request_headers=[],
            sleep_interval=4,
            should_be_cached=False,
        )

    def test_global_cache_ttl_3_sleep_4_max_age_10(self):
        """
        Response must be from cache if:
            - max-age is present in response;
            - sleep < max-age;
        cache_ttl is ignored.
        """
        self.base_scenario(
            response_headers=[("cache-control", "max-age=10")],
            request_headers=[],
            second_request_headers=[],
            sleep_interval=4,
            should_be_cached=True,
        )

    def test_global_cache_ttl_3_sleep_2_max_age_1(self):
        """
        Response must not be from cache if:
            - max-age is present in response;
            - sleep > max-age;
        cache_ttl is ignored.
        """
        self.base_scenario(
            response_headers=[("cache-control", "max-age=1")],
            request_headers=[],
            second_request_headers=[],
            sleep_interval=2,
            should_be_cached=False,
        )

    def test_global_cache_ttl_3_sleep_2_s_maxage_1(self):
        """
        Response must not be from cache if:
            - max-age is present in response;
            - sleep > s-maxage;
        cache_ttl is ignored.
        """
        self.base_scenario(
            response_headers=[("cache-control", "s-maxage=1")],
            request_headers=[],
            second_request_headers=[],
            sleep_interval=2,
            should_be_cached=False,
        )

    def test_vhost_cache_ttl_1_sleep_2(self):
        self.base_scenario(
            response_headers=[],
            request_headers=[("cookie", "comment_author_name=john")],
            second_request_headers=[("cookie", "comment_author_name=john")],
            sleep_interval=2,
            should_be_cached=False,
        )

    def test_vhost_cache_ttl_1_sleep_4(self):
        self.base_scenario(
            response_headers=[],
            request_headers=[("cookie", "comment_author_name=john")],
            second_request_headers=[("cookie", "comment_author_name=john")],
            sleep_interval=4,  # great than global cache ttl
            should_be_cached=False,
        )

    def test_priority_for_cache_control_header_no_cache(self):
        """Cache-Control header has priority over cache_ttl."""
        self.base_scenario(
            response_headers=[("cache-control", "no-cache")],
            request_headers=[("cookie", "comment_author_name=john")],
            second_request_headers=[("cookie", "comment_author_name=john")],
            sleep_interval=0,
            should_be_cached=False,
        )

    def test_priority_for_cache_control_header_no_store(self):
        """Cache-Control header has priority over cache_ttl."""
        self.base_scenario(
            response_headers=[("cache-control", "no-store")],
            request_headers=[("cookie", "comment_author_name=john")],
            second_request_headers=[("cookie", "comment_author_name=john")],
            sleep_interval=0,
            should_be_cached=False,
        )

    def test_priority_for_cache_control_header_private(self):
        """Cache-Control header has priority over cache_ttl."""
        self.base_scenario(
            response_headers=[("cache-control", "private")],
            request_headers=[("cookie", "comment_author_name=john")],
            second_request_headers=[("cookie", "comment_author_name=john")],
            sleep_interval=0,
            should_be_cached=False,
        )


class TestH2CacheDisable(tester.TempestaTest):
    tempesta = {
        "config": """
listen 80;
listen 443 proto=h2;

tls_match_any_server_name;
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;

server ${server_ip}:8000;
frang_limits {http_strict_host_checking false;}
vhost vh1 {
    proxy_pass default;
}

cache 2;
cache_fulfill * *;
http_chain {
    cookie "foo_items_in_cart" == "*" -> cache_disable = 1;
    cookie "comment_author_*" == "*" -> cache_disable = 0;
    cookie "wordpress_logged_in*" == "*" -> cache_disable;
    -> vh1;
}
"""
    }

    clients = [DEPROXY_CLIENT_H2]

    backends = [DEPROXY_SERVER]

    def base_scenario(
        self,
        request_headers: list,
        second_request_headers: list,
        should_be_cached: bool,
    ):
        self.start_all_services()

        server = self.get_server("deproxy")

        client = self.get_client("deproxy")
        client.send_request(
            client.create_request(method="GET", headers=request_headers, uri="/"),
            "200",
        )
        client.send_request(
            client.create_request(method="GET", headers=second_request_headers, uri="/"),
            "200",
        )

        self.assertEqual(1 if should_be_cached else 2, len(server.requests))

    def test_cache_disable(self):
        self.base_scenario(
            request_headers=[("cookie", "wordpress_logged_in=true")],
            second_request_headers=[("cookie", "wordpress_logged_in=true")],
            should_be_cached=False,
        )

    def test_cache_disable_0(self):
        self.base_scenario(
            request_headers=[("cookie", "comment_author_name=john")],
            second_request_headers=[("cookie", "comment_author_name=john")],
            should_be_cached=True,
        )

    def test_cache_disable_1(self):
        self.base_scenario(
            request_headers=[("cookie", "foo_items_in_cart=")],
            second_request_headers=[("cookie", "foo_items_in_cart=")],
            should_be_cached=False,
        )

    def test_cache_disable_with_override_http_chain(self):
        self.base_scenario(
            request_headers=[("cookie", "foo_items_in_cart=; comment_author_name=john")],
            second_request_headers=[("cookie", "foo_items_in_cart=; comment_author_name=john")],
            should_be_cached=True,
        )


class TestChunkedResponse(tester.TempestaTest):
    """
    Cached data of the chunked response
    should be equal to the original data.
    """

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
        listen 443 proto=h2;
        tls_match_any_server_name;
        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        frang_limits {http_strict_host_checking false;}
        cache 1;
        cache_fulfill * *;
        server ${server_ip}:8000;
        """
    }

    clients = [
        {
            "id": "http1",
            "type": "curl",
            "cmd_args": (
                # Disable HTTP decoding, chunked data should be compared
                " --raw"
                # Prevent hang on invalid response
                " --max-time 1"
            ),
        },
        {
            "id": "http2",
            "type": "curl",
            "http2": True,
            "cmd_args": (
                # Disable HTTP decoding, chunked data should be compared
                " --raw"
                # Prevent hang on invalid response
                " --max-time 1"
            ),
        },
    ]

    def get_response(self, client) -> CurlResponse:
        client.start()
        self.wait_while_busy(client)
        client.stop()
        return client.last_response

    def test_h2_cached_data_equal_to_original(self):
        self.get_simple_and_cache_response(
            client=self.get_client("http2"), resp_body_for_first_request="test-data"
        )

    def test_cached_data_equal_to_original(self):
        self.get_simple_and_cache_response(
            client=self.get_client("http1"),
            resp_body_for_first_request="9\r\ntest-data\r\n0\r\n\r\n",
        )

    def get_simple_and_cache_response(self, client, resp_body_for_first_request):
        self.start_all_services(client=False)
        srv = self.get_server("chunked")

        with self.subTest("Get non-cached response"):
            response = self.get_response(client)
            self.assertEqual(response.status, 200, response)
            self.assertNotIn("age", response.headers)
            self.assertEqual(response.stdout, resp_body_for_first_request)

        with self.subTest("Get cached response"):
            response = self.get_response(client)
            self.assertEqual(response.status, 200, response)
            cached_data = response.stdout
            # check that response is from the cache
            self.assertEqual(len(srv.requests), 1)
            self.assertIn("age", response.headers)
            # Cached response is dechunked after the #1418
            self.assertEqual(response.stdout, "test-data")


class TestCacheVhost(tester.TempestaTest):
    clients = [
        {
            "id": "front-1",
            "type": "external",
            "binary": "curl",
            "cmd_args": (
                " -k"
                " --max-time 1"
                " -H 'Host: frontend'"
                " --connect-to tempesta-tech.com:443:${tempesta_ip}:443"
                " https://tempesta-tech.com/file.html"
            ),
        },
        {
            "id": "front-2",
            "type": "external",
            "binary": "curl",
            "cmd_args": (
                " -k"
                " --max-time 1"
                " -H 'Host: frontend'"
                " --connect-to tempesta-tech.com:443:${tempesta_ip}:443"
                " https://tempesta-tech.com/file.html"
            ),
        },
        {
            "id": "debian-1",
            "type": "external",
            "binary": "curl",
            "cmd_args": (
                " -k"
                " --max-time 1"
                " --connect-to tempesta-tech.com:443:${tempesta_ip}:443"
                " https://tempesta-tech.com/file.html"
            ),
        },
    ]

    backends = [
        {
            "id": "srv_main",
            "type": "deproxy",
            "port": "8080",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 3\r\n\r\nfoo",
        },
        {
            "id": "srv_front",
            "type": "deproxy",
            "port": "8081",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 3\r\n\r\nbar",
        },
    ]

    tempesta = {
        "config": """
        listen 443 proto=h2;
        listen 80;

        srv_group main {
                server ${server_ip}:8080;
        }

        srv_group front {
                server ${server_ip}:8081;
        }
        frang_limits {http_strict_host_checking false;}
        vhost tempesta-tech.com {
                tls_certificate ${tempesta_workdir}/tempesta.crt;
                tls_certificate_key ${tempesta_workdir}/tempesta.key;
                proxy_pass main;
        }

        vhost frontend {
                proxy_pass front;
        }

        http_chain {
                host == "frontend" -> frontend;
                host == "tempesta-tech.com" -> tempesta-tech.com;
                -> block;
        }

        cache_fulfill * *;
        """
    }

    def get_response(self, client) -> CurlResponse:
        client.start()
        self.wait_while_busy(client)
        client.stop()
        return client.response_msg

    def test_h2(self):
        self.start_all_services(client=False)

        # Fetch response from the backend
        srv = self.get_server("srv_front")
        client = self.get_client("front-1")
        response = self.get_response(client)
        self.assertEqual(len(srv.requests), 1, "Request should be taken from srv_front")
        self.assertEqual(response, "bar")

        # Make sure it was cached
        srv = self.get_server("srv_front")
        client = self.get_client("front-2")
        response = self.get_response(client)
        self.assertEqual(len(srv.requests), 1, "Request should be taken from cache")
        self.assertEqual(response, "bar")

        # Send request to the different vhost. Make sure that
        # we're not geting cached response for the first vhost
        srv = self.get_server("srv_main")
        client = self.get_client("debian-1")
        response = self.get_response(client)
        self.assertEqual(len(srv.requests), 1, "Request should be taken from srv_main")
        self.assertEqual(response, "foo")

    def test_http1(self):
        tempesta = self.get_tempesta()
        tempesta.config.defconfig = tempesta.config.defconfig.replace("h2", "https")
        self.test_h2()


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
