"""Functional tests of caching config."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import string
import time
from http import HTTPStatus

from framework.curl_client import CurlResponse
from framework.deproxy_client import DeproxyClientH2
from framework.deproxy_server import StaticDeproxyServer
from helpers import deproxy, error, remote
from helpers.control import Tempesta
from helpers.deproxy import HttpMessage
from test_suite import checks_for_tests as checks
from test_suite import marks, tester

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

DEPROXY_CLIENT_SSL = {
    "id": "deproxy",
    "type": "deproxy",
    "addr": "${tempesta_ip}",
    "port": "443",
    "ssl": True,
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


@marks.parameterize_class(
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


@marks.parameterize_class(
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

    @marks.Parameterize.expand(
        [
            marks.Param(name="raw", header_name="hdr", val1="aaa", val2="bbb"),
            marks.Param(
                name="regular",
                header_name="content-encoding",
                val1="aaa",
                val2="bbb",
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


@marks.parameterize_class(
    [
        {"name": "Http", "clients": [DEPROXY_CLIENT]},
        {"name": "H2", "clients": [DEPROXY_CLIENT_H2]},
    ]
)
class TestQueryparamsAndRedirect(tester.TempestaTest):
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

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="different_key",
                uri_1="/pic.jpg?param1=value1",
                uri_2="/pic.jpg?param2=value1",
                should_be_cached=False,
            ),
            marks.Param(
                name="different_value",
                uri_1="/pic.jpg?param1=value1",
                uri_2="/pic.jpg?param1=value2",
                should_be_cached=False,
            ),
            marks.Param(
                name="with_new_param",
                uri_1="/pic.jpg?param1=value1",
                uri_2="/pic.jpg?param1=value1&param2=value2",
                should_be_cached=False,
            ),
            marks.Param(
                name="with_new_param",
                uri_1="/pic.jpg?param1=value1",
                uri_2="/pic.jpg?param1=value1&param1=value1",
                should_be_cached=False,
            ),
            marks.Param(
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

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="300_multiple_choices",
                response=HTTPStatus.MULTIPLE_CHOICES,
                should_be_cached=True,
            ),
            marks.Param(
                name="301_moved_permanently",
                response=HTTPStatus.MOVED_PERMANENTLY,
                should_be_cached=True,
            ),
            marks.Param(
                name="302_found",
                response=HTTPStatus.FOUND,
                should_be_cached=False,
            ),
            marks.Param(
                name="303_see_other",
                response=HTTPStatus.SEE_OTHER,
                should_be_cached=False,
            ),
            marks.Param(
                name="304_not_modified",
                response=HTTPStatus.NOT_MODIFIED,
                should_be_cached=False,
            ),
            marks.Param(
                name="305_user_proxy",
                response=HTTPStatus.USE_PROXY,
                should_be_cached=False,
            ),
            marks.Param(
                name="307_temporary_redirect",
                response=HTTPStatus.TEMPORARY_REDIRECT,
                should_be_cached=False,
            ),
            marks.Param(
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


@marks.parameterize_class(
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


@marks.parameterize_class(
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

    @marks.Parameterize.expand(
        [
            marks.Param(
                "GET_after_GET", first_method="GET", second_method="GET", should_be_cached=True
            ),
            marks.Param(
                "HEAD_after_GET", first_method="GET", second_method="HEAD", should_be_cached=True
            ),
            marks.Param(
                "POST_after_GET", first_method="GET", second_method="POST", should_be_cached=False
            ),
            marks.Param(
                "HEAD_after_HEAD", first_method="HEAD", second_method="HEAD", should_be_cached=True
            ),
            marks.Param(
                "GET_after_HEAD", first_method="HEAD", second_method="GET", should_be_cached=True
            ),
            marks.Param(
                "POST_after_HEAD", first_method="HEAD", second_method="POST", should_be_cached=False
            ),
        ]
    )
    def test(self, name, first_method, second_method, should_be_cached):
        """
        The response to a GET request is cacheable; a cache MAY use it to
        satisfy subsequent GET and HEAD requests.
        RFC 9110 9.3.1

        For HEAD method Tempesta overrides HEAD with GET, sends request
        to upstream to cache full response, but returns to client response
        with only headers as expected for HEAD request.
        """
        if first_method == "HEAD":
            self.disable_deproxy_auto_parser()
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

    @marks.Parameterize.expand(
        [
            marks.Param(name="PUT_request", method="PUT"),
            marks.Param(name="DELETE_request", method="DELETE"),
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

    @marks.Parameterize.expand(
        [
            marks.Param(name="GET", second_method="GET", should_be_cached=True),
            marks.Param(name="HEAD", second_method="HEAD", should_be_cached=True),
            marks.Param(name="POST", second_method="POST", should_be_cached=False),
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

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="not_same_location",
                extra_header="Content-Location: /index1.html\r\n"
                + "Cache-Control: public, s-maxage=5\r\n",
            ),
            marks.Param(name="no_cache_control", extra_header="Content-Location: /index.html\r\n"),
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

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="GET_POST",
                first_method="GET",
                second_method="POST",
                second_headers=[],
                sleep_interval=0,
            ),
            marks.Param(
                name="GET_GET",
                first_method="GET",
                second_method="GET",
                second_headers=[("cache-control", "max-age=1")],
                sleep_interval=2,
            ),
            marks.Param(
                name="GET_HEAD",
                first_method="GET",
                second_method="HEAD",
                second_headers=[("cache-control", "max-age=1")],
                sleep_interval=2,
            ),
            marks.Param(
                name="POST_POST",
                first_method="POST",
                second_method="POST",
                second_headers=[],
                sleep_interval=0,
            ),
            marks.Param(
                name="POST_GET",
                first_method="POST",
                second_method="GET",
                second_headers=[("cache-control", "max-age=1")],
                sleep_interval=2,
            ),
            marks.Param(
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
        Tempesta can't save several entries in cache. Fresh record with the same key overrides
        old, each HEAD request transoforms to GET during forwarding to upstream.
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

        # Send second request. Tempesta FW forwards request to backend server and saves response in
        # cache overriding already stored record with new fresh record. (for some requests we use
        # cache-control directive to be shure that request will be forwarded to backend server).
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
        # Tempesta FW satisfy request from cache, using signle stored entry.
        # When the second request has GET or POST method, Tempesta FW uses
        # it to satisfy third request, because it is the freshest cache entry.
        # Even if second request has HEAD method, we will use this response,
        # because we have only one record per key and we always do GET request
        # to upstream not regarding of the request method.
        #
        self.assertEqual(
            "Second body." if second_method != "HEAD" else "", client.last_response.body
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
            tempesta_config="cache_bypass * *;\ncache_resp_hdr_del content-encoding remove-me-2;\n",
            response_headers=[("content-encoding", "gzip"), ("remove-me-2", "")],
            expected_cached_headers=[("content-encoding", "gzip"), ("remove-me-2", "")],
            should_be_cached=False,
        )

    def test_cache_fulfill_and_hdr_del(self):
        self.base_scenario(
            tempesta_config="cache_fulfill * *;\ncache_resp_hdr_del content-encoding remove-me-2;\n",
            response_headers=[("content-encoding", "gzip"), ("remove-me-2", "")],
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

    @marks.Parameterize.expand(
        [
            marks.Param(name="h2", proto="h2"),
            marks.Param(name="https", proto="https"),
        ]
    )
    def test(self, name, proto):
        """
        Tempesta should not override cached response.
        It may happens during transfer the first cached response.
        To check it this we must do 3 requests:
        1. Not from cache.
        2. From cache, here cache may be corrupted.
        3. From cache, here check validity.
        """
        self.get_tempesta().config.set_defconfig(
            f"listen 443 proto={proto};\r\n" + self.get_tempesta().config.defconfig
        )
        self.start_all_services(client=False)

        # Fetch response from the backend
        srv = self.get_server("srv_front")
        client = self.get_client("front-1")
        response = self.get_response(client)
        self.assertEqual(len(srv.requests), 1, "Request should be taken from srv_front")
        self.assertEqual(response, "bar")

        srv = self.get_server("srv_front")
        client = self.get_client("front-1")
        response = self.get_response(client)
        self.assertEqual(len(srv.requests), 1, "Request should be taken from cache")
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


LONG_HEADERS_BACKEND = {
    "id": "python_hello",
    "type": "docker",
    "image": "python",
    "ports": {8000: 8000},
    "cmd_args": "hello.py --body %s -H '%s'" % ("a" * 10000, "b: " + "b" * 71000),
}

LONG_BODY_BACKEND = {
    "id": "python_hello",
    "type": "docker",
    "image": "python",
    "ports": {8000: 8000},
    "cmd_args": "hello.py --body %s -H '%s'" % ("a" * 100000, "b: " + "b" * 10000),
}


@marks.parameterize_class(
    [
        {"name": "HttpHeaders", "clients": [DEPROXY_CLIENT], "backends": [LONG_HEADERS_BACKEND]},
        {"name": "HttpBody", "clients": [DEPROXY_CLIENT], "backends": [LONG_BODY_BACKEND]},
        {
            "name": "HttpsHeaders",
            "clients": [DEPROXY_CLIENT_SSL],
            "backends": [LONG_HEADERS_BACKEND],
        },
        {"name": "HttpsBody", "clients": [DEPROXY_CLIENT_SSL], "backends": [LONG_BODY_BACKEND]},
        {"name": "H2Headers", "clients": [DEPROXY_CLIENT_H2], "backends": [LONG_HEADERS_BACKEND]},
        {"name": "H2Body", "clients": [DEPROXY_CLIENT_H2], "backends": [LONG_BODY_BACKEND]},
    ]
)
class TestCacheDocker(tester.TempestaTest):
    """
    This class contains checks how Tempesta FW cache responses,
    from Docker backend (this responses contain skb with
    SKBTX_SHARED_FRAG flag).
    """

    tempesta = {
        "config": """
listen 80;
listen 443 proto=h2,https;
cache 2;
cache_fulfill * *;
server ${server_ip}:8000;
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
frang_limits {
    http_strict_host_checking false;
}
""",
    }

    def test(self):
        tempesta: Tempesta = self.get_tempesta()
        self.start_all_services()

        client = self.get_client("deproxy")
        if isinstance(client, DeproxyClientH2):
            """
            When we use LONG_HEADERS_BACKEND response headers length is
            greater then 65536, so we should change initial settings to
            prevent response dropping.
            """
            client.update_initial_settings(max_header_list_size=65536 * 2)
            client.send_bytes(client.h2_connection.data_to_send())
            client.h2_connection.clear_outbound_data_buffer()
            self.assertTrue(
                client.wait_for_ack_settings(),
                "Tempesta foes not returns SETTINGS frame with ACK flag.",
            )
        request = client.create_request(method="GET", uri="/", headers=[])

        for _ in range(3):
            client.send_request(request, expected_status_code="200")

        self.assertNotIn("age", client.responses[0].headers)
        checks.check_tempesta_cache_stats(
            tempesta,
            cache_hits=2,
            cache_misses=1,
            cl_msg_served_from_cache=2,
        )
        for response in client.responses[1:]:  # Note WPS 440
            self.assertIn("age", response.headers)


class TestCacheClean(tester.TempestaTest):
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
        {"id": "deproxy", "type": "deproxy", "port": "8080", "response": "static"},
    ]

    tempesta = {
        "config": """
        listen 443 proto=h2;

        srv_group main {
                server ${server_ip}:8080;
        }

       vhost tempesta-tech.com {
                tls_certificate ${tempesta_workdir}/tempesta.crt;
                tls_certificate_key ${tempesta_workdir}/tempesta.key;
                proxy_pass main;
        }

        http_chain {
            -> tempesta-tech.com;
        }

        cache_fulfill * *;
        cache 2;
        """
    }

    def test(self):
        """
        Only for cache REPLICA mode, SHARD mode is not expected.

        Send request, Tempesta cache it, wait for max-age time then send second request.
        At this stage we expected that first request evicted from cache and only new version
        is presented in the cache. Send third request with different uri to verify we don't clean
        up records with different uri.
        """
        self.start_all_services()
        server = self.get_server("deproxy")
        client = self.get_client("deproxy")
        tempesta = self.get_tempesta()
        nodes_num = remote.tempesta.get_numa_nodes_count()

        server.set_response(
            f"HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-Length: 0\r\n"
            + "Cache-control: max-age=1\r\n"
            + "\r\n"
        )

        request = client.create_request(
            uri="/", authority="tempesta-tech.com", method="GET", headers=[]
        )

        # Send two requests with interval greater than max-age to let record become stale
        client.send_request(request, expected_status_code="200")
        time.sleep(3)
        client.send_request(request, expected_status_code="200")

        # We testing cache REPLICA mode, thus we expect response will be copied to each numa node
        expected_objects_num = nodes_num
        tempesta.get_stats()
        self.assertEqual(tempesta.stats.cache_objects, expected_objects_num)

        request = client.create_request(
            uri="/2", authority="tempesta-tech.com", method="GET", headers=[]
        )
        client.send_request(request, expected_status_code="200")

        expected_objects_num = nodes_num * 2
        tempesta.get_stats()
        self.assertEqual(tempesta.stats.cache_objects, expected_objects_num)


class TestCacheUseStaleCfg(tester.TempestaTest):
    """
    Class for testing "cache_use_stale" configuration.
    """

    tempesta = {
        "config": """
listen 443 proto=h2;

srv_group default {
    server ${server_ip}:8000;
}
tls_match_any_server_name;
vhost default {
    proxy_pass default;
    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;
}
cache 2;
cache_fulfill * *;
"""
    }

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="dupl",
                cfg="cache_use_stale 5*;cache_use_stale 4*;\n",
                expected_msg="duplicate entry: 'cache_use_stale'",
            ),
            marks.Param(
                name="wrong_mask",
                cfg="cache_use_stale 3*;\n",
                expected_msg='cache_use_stale Unsupported argument "3\*"',
            ),
            marks.Param(
                name="wrong_code",
                cfg="cache_use_stale 200;\n",
                expected_msg="Please specify status code above than 399",
            ),
        ]
    )
    def test_cache_use_stale_config(self, name, cfg, expected_msg):
        """
        Test misconfiguration of `cache_use_stale` directive.
        """
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(tempesta.config.defconfig + cfg)
        self.oops_ignore.append("ERROR")

        with self.assertRaises(error.ProcessBadExitStatusException):
            self.start_tempesta()

        self.assertTrue(self.loggers.dmesg.find(expected_msg))


class TestCacheResponseWithTrailersBase(tester.TempestaTest):
    tempesta = {
        "config": """
listen 80;
listen 443 proto=h2;
server ${server_ip}:8000;
cache 2;
cache_methods GET HEAD;
cache_fulfill * *;
tls_match_any_server_name;
vhost default {
    proxy_pass default;
    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;
}
""",
    }

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n",
        }
    ]

    def encode_chunked(self, data, chunk_size=256):
        result = ""
        while len(data):
            chunk, data = data[:chunk_size], data[chunk_size:]
            result += f"{hex(len(chunk))[2:]}\r\n"
            result += f"{chunk}\r\n"
        return result + "0\r\n\r\n"

    def start_and_check_first_response(self, client, method, response, tr1, tr2):
        self.start_all_services()

        srv: StaticDeproxyServer = self.get_server("deproxy")
        srv.set_response(response)

        request = client.create_request(method=method, headers=[])
        client.send_request(request, "200")

        self.assertEqual(client.last_response.headers.get("Trailer"), f"{tr1} {tr2}")

    def check_second_request(self, *, client, method, tr1, tr2):
        request = client.create_request(method=method, headers=[])
        client.send_request(request, "200")
        self.assertIn("age", client.last_response.headers)

        self.assertIsNone(client.last_response.headers.get("Transfer-Encoding"))
        self.assertEqual(client.last_response.headers.get("Trailer"), f"{tr1} {tr2}")
        self.assertIsNone(client.last_response.trailer.get(tr1))
        self.assertIsNone(client.last_response.trailer.get(tr2))


@marks.parameterize_class(
    [
        {"name": "Http", "clients": [DEPROXY_CLIENT]},
        {"name": "H2", "clients": [DEPROXY_CLIENT_H2]},
    ]
)
class TestCacheResponseWithTrailers(TestCacheResponseWithTrailersBase):
    """
    This class contains checks for tempesta cache config and trailers
    in response.
    These tests use asserts from DeproxyAutoParser.
    They MUST NOT call `self.disable_deproxy_auto_parser()` method.
    """

    @marks.Parameterize.expand(
        [
            marks.Param(name="GET_GET", method1="GET", method2="GET"),
            marks.Param(name="HEAD_GET", method1="HEAD", method2="GET"),
            marks.Param(name="GET_HEAD", method1="GET", method2="HEAD"),
            marks.Param(name="HEAD_HEAD", method1="HEAD", method2="HEAD"),
        ]
    )
    def test(self, name, method1, method2):
        client = self.get_client("deproxy")

        self.start_and_check_first_response(
            client=client,
            method=method1,
            response="HTTP/1.1 200 OK\r\n"
            + "Content-type: text/html\r\n"
            + f"Last-Modified: {deproxy.HttpMessage.date_time_string()}\r\n"
            + f"Date: {deproxy.HttpMessage.date_time_string()}\r\n"
            + "Server: Deproxy Server\r\n"
            + "Transfer-Encoding: chunked\r\n"
            + "Trailer: X-Token1 X-Token2\r\n\r\n"
            + self.encode_chunked(string.ascii_letters, 16)[:-2]
            + f"X-Token1: value1\r\n"
            + f"X-Token2: value2\r\n\r\n",
            tr1="X-Token1",
            tr2="X-Token2",
        )
        self.check_second_request(client=client, method=method2, tr1="X-Token1", tr2="X-Token2")

    def test_empty_body_head_to_get(self):
        client = self.get_client("deproxy")

        self.start_and_check_first_response(
            client=client,
            method="HEAD",
            response="HTTP/1.1 200 OK\r\n"
            + "Content-type: text/html\r\n"
            + f"Last-Modified: {deproxy.HttpMessage.date_time_string()}\r\n"
            + f"Date: {deproxy.HttpMessage.date_time_string()}\r\n"
            + "Server: Deproxy Server\r\n"
            + "Transfer-Encoding: chunked\r\n"
            + "Trailer: X-Token1 X-Token2\r\n\r\n"
            + "0\r\n"
            + f"X-Token1: value1\r\n"
            + f"X-Token2: value2\r\n\r\n",
            tr1="X-Token1",
            tr2="X-Token2",
        )
        self.check_second_request(client=client, method="GET", tr1="X-Token1", tr2="X-Token2")

    def test_same_hdr_and_trailer_head_to_get(self):
        client = self.get_client("deproxy")

        self.start_and_check_first_response(
            client=client,
            method="HEAD",
            response="HTTP/1.1 200 OK\r\n"
            + "Content-type: text/html\r\n"
            + f"Last-Modified: {deproxy.HttpMessage.date_time_string()}\r\n"
            + f"Date: {deproxy.HttpMessage.date_time_string()}\r\n"
            + "Server: Deproxy Server\r\n"
            + "Transfer-Encoding: chunked\r\n"
            + "hdr_and_trailer: header\r\n"
            + "Trailer: hdr_and_trailer X-Token2\r\n\r\n"
            + "0\r\n"
            + f"hdr_and_trailer: trailer\r\n"
            + f"X-Token2: value2\r\n\r\n",
            tr1="hdr_and_trailer",
            tr2="X-Token2",
        )
        self.assertEqual(client.last_response.headers.get("hdr_and_trailer"), "header")
        self.assertIsNone(client.last_response.trailer.get("hdr_and_trailer"))

        self.check_second_request(
            client=client, method="GET", tr1="hdr_and_trailer", tr2="X-Token2"
        )
        self.assertEqual(client.last_response.headers.get("hdr_and_trailer"), "header")
        self.assertIsNone(client.last_response.trailer.get("hdr_and_trailer"))

    def test_same_trailer_head_to_get(self):
        client = self.get_client("deproxy")

        self.start_and_check_first_response(
            client=client,
            method="HEAD",
            response="HTTP/1.1 200 OK\r\n"
            + "Content-type: text/html\r\n"
            + f"Last-Modified: {deproxy.HttpMessage.date_time_string()}\r\n"
            + f"Date: {deproxy.HttpMessage.date_time_string()}\r\n"
            + "Server: Deproxy Server\r\n"
            + "Transfer-Encoding: chunked\r\n"
            + "Trailer: trailer_and_trailer trailer_and_trailer\r\n\r\n"
            + "0\r\n"
            + f"trailer_and_trailer: value1\r\n"
            + f"trailer_and_trailer: value2\r\n\r\n",
            tr1="trailer_and_trailer",
            tr2="trailer_and_trailer",
        )

        if isinstance(client, DeproxyClientH2):
            self.assertEqual(
                tuple(client.last_response.headers.find_all("trailer_and_trailer")),
                ("value1", "value2"),
            )
        else:
            self.assertIsNone(client.last_response.headers.get("trailer_and_trailer"))

        self.check_second_request(
            client=client, method="GET", tr1="trailer_and_trailer", tr2="trailer_and_trailer"
        )
        self.assertEqual(
            tuple(client.last_response.headers.find_all("trailer_and_trailer")),
            ("value1", "value2"),
            "The response from cache MUST contain trailers in headers.",
        )

    @marks.Parameterize.expand(
        [
            marks.Param(name="GET_GET", method1="GET", method2="GET"),
            marks.Param(name="HEAD_GET", method1="HEAD", method2="GET"),
        ]
    )
    def test_server_in_trailers(self, name, method1, method2):
        client = self.get_client("deproxy")

        self.start_and_check_first_response(
            client=client,
            method=method1,
            response="HTTP/1.1 200 OK\r\n"
            + "Content-type: text/html\r\n"
            + f"Last-Modified: {deproxy.HttpMessage.date_time_string()}\r\n"
            + f"Date: {deproxy.HttpMessage.date_time_string()}\r\n"
            + "Transfer-Encoding: chunked\r\n"
            + "Trailer: Server X-Token2\r\n\r\n"
            + "0\r\n"
            + f"Server: cloudfare\r\n"
            + f"X-Token2: value2\r\n\r\n",
            tr1="Server",
            tr2="X-Token2",
        )
        self.assertEqual(client.last_response.headers.get("Server"), "Tempesta FW/0.8.0")

        self.check_second_request(client=client, method=method2, tr1="Server", tr2="X-Token2")
        self.assertEqual(client.last_response.headers.get("Server"), "Tempesta FW/0.8.0")

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="mix_GET",
                method="GET",
                tr1="Connection",
                tr1_val="keep-alive",
                tr2="X-Token1",
                tr2_val="value1",
            ),
            marks.Param(
                name="hbp_GET",
                method="GET",
                tr1="Connection",
                tr1_val="keep-alive",
                tr2="Keep-Alive",
                tr2_val="timeout=5, max=100",
            ),
            marks.Param(
                name="mix_HEAD",
                method="HEAD",
                tr1="Connection",
                tr1_val="keep-alive",
                tr2="X-Token1",
                tr2_val="value1",
            ),
            marks.Param(
                name="hbp_HEAD",
                method="HEAD",
                tr1="Connection",
                tr1_val="keep-alive",
                tr2="Keep-Alive",
                tr2_val="timeout=5, max=100",
            ),
        ]
    )
    def test_hbh_headers(self, name, method, tr1, tr1_val, tr2, tr2_val):
        client = self.get_client("deproxy")

        self.start_and_check_first_response(
            client=client,
            method=method,
            response="HTTP/1.1 200 OK\r\n"
            + "Content-type: text/html\r\n"
            + f"Last-Modified: {deproxy.HttpMessage.date_time_string()}\r\n"
            + f"Date: {deproxy.HttpMessage.date_time_string()}\r\n"
            + "Server: Deproxy Server\r\n"
            + "Transfer-Encoding: chunked\r\n"
            + f"Trailer: {tr1} {tr2}\r\n\r\n"
            + self.encode_chunked(string.ascii_letters, 16)[:-2]
            + f"{tr1}: {tr1_val}\r\n"
            + f"{tr2}: {tr2_val}\r\n\r\n",
            tr1=tr1,
            tr2=tr2,
        )

        self.check_second_request(client=client, method=method, tr1=tr1, tr2=tr2)


class TestCacheResponseWithCacheDifferentClients(TestCacheResponseWithTrailersBase):
    """
    Same as previous but requests made from different clients.
    These tests use asserts from DeproxyAutoParser.
    They MUST NOT call `self.disable_deproxy_auto_parser()` method.
    """

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
        {
            "id": "deproxy_h2",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="GET_deproxy_deproxy_h2",
                client_id1="deproxy",
                client_id2="deproxy_h2",
                method="GET",
            ),
            marks.Param(
                name="HEAD_deproxy_deproxy_h2",
                client_id1="deproxy",
                client_id2="deproxy_h2",
                method="HEAD",
            ),
            marks.Param(
                name="GET_deproxy_h2_deproxy",
                client_id1="deproxy_h2",
                client_id2="deproxy",
                method="GET",
            ),
            marks.Param(
                name="HEAD_deproxy_h2_deproxy",
                client_id1="deproxy_h2",
                client_id2="deproxy",
                method="HEAD",
            ),
        ]
    )
    def test(self, name, client_id1, client_id2, method):
        client1 = self.get_client(client_id1)
        client2 = self.get_client(client_id2)

        self.start_and_check_first_response(
            client=client1,
            method="GET",
            response="HTTP/1.1 200 OK\r\n"
            + "Content-type: text/html\r\n"
            + f"Last-Modified: {deproxy.HttpMessage.date_time_string()}\r\n"
            + f"Date: {deproxy.HttpMessage.date_time_string()}\r\n"
            + "Server: Deproxy Server\r\n"
            + "Transfer-Encoding: chunked\r\n"
            + "Trailer: X-Token1 X-Token2\r\n\r\n"
            + self.encode_chunked(string.ascii_letters, 16)[:-2]
            + f"X-Token1: value1\r\n"
            + f"X-Token2: value2\r\n\r\n",
            tr1="X-Token1",
            tr2="X-Token2",
        )
        self.check_second_request(client=client2, method=method, tr1="X-Token1", tr2="X-Token2")


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
