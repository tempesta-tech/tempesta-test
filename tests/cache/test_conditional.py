"""Functional tests of caching different methods."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

import unittest

from framework.deproxy import HttpMessage
from framework.deproxy_client import DeproxyClient
from framework.deproxy_server import StaticDeproxyServer
from test_suite import marks
from test_suite.tester import TempestaTest

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
class TestConditional(TempestaTest):
    """There are checks for 'if-none-match' and 'if-modified-since' headers in request."""

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
cache_methods GET HEAD POST;
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

    def _test(
        self,
        etag: str,
        expected_status_code: str,
        expected_etag_200: str = None,
        expected_etag_304: str = None,
        if_none_match: str = None,
        if_modified_since: str = None,
        method: str = "GET",
    ):
        """
        Send GET or HEAD request and receive 'Etag' header. Repeat request with correct/incorrect
        'if-none-match' and 'if-modified-since' headers.
        """
        self.start_all_services()
        srv: StaticDeproxyServer = self.get_server("deproxy")
        client: DeproxyClient = self.get_client("deproxy")

        srv.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-Length: 13\r\n"
            + "Content-Type: text/html\r\n"
            + "Server: Deproxy Server\r\n"
            + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + f"Etag: {etag}\r\n"
            + "\r\n"
            + "<html></html>",
        )

        if not expected_etag_200:
            expected_etag_200 = etag
        if not expected_etag_304:
            expected_etag_304 = etag

        client.send_request(
            request=client.create_request(method="GET", uri="/page.html", headers=[]),
            expected_status_code="200",
        )
        self.assertIn(expected_etag_200, str(client.last_response))

        if if_none_match and if_modified_since:
            option_header = [
                ("if-none-match", if_none_match),
                (f"if-modified-since", if_modified_since),
            ]
        elif if_none_match:
            option_header = [("if-none-match", if_none_match)]
        elif if_modified_since:
            option_header = [("if-modified-since", if_modified_since)]
        else:
            option_header = []

        client.send_request(
            request=client.create_request(method=method, uri="/page.html", headers=option_header),
            expected_status_code=expected_status_code,
        )

        if expected_status_code != "412":
            self.assertIn(expected_etag_304, client.last_response.headers["etag"])
        self.assertEqual(len(srv.requests), 1, "Server has received unexpected number of requests.")

    """
    According to RFC 9110 13.1.2:
    To evaluate a received If-None-Match header field:
    1. If the field value is "*", the condition is false if the origin server
       has a current representation for the target resource.
    2. If the field value is a list of entity tags, the condition is false if
       one of the listed tags matches the entity tag of the selected representation.
    3. Otherwise, the condition is true.

    An origin server that evaluates an If-None-Match condition MUST NOT perform the
    requested method if the condition evaluates to false; instead, the origin server
    MUST respond with either a) the 304 (Not Modified) status code if the request method
    is GET or HEAD or b) the 412 (Precondition Failed) status code for all other request
    methods.
    """

    def test_none_match(self):
        """Client has cached resource, send 304."""
        self._test(
            etag='"asdfqwerty"',
            expected_status_code="304",
            if_none_match='"asdfqwerty"',
            if_modified_since=None,
            method="GET",
        )

    def test_none_match_HEAD(self):
        """Client has cached resource, send 304."""
        self._test(
            etag='"asdfqwerty"',
            expected_status_code="304",
            if_none_match='"asdfqwerty"',
            if_modified_since=None,
            method="HEAD",
        )

    def test_none_match_no_quotes_etag(self):
        """Same as test_none_match(), but etag isn't enclosed in double quotes."""
        self._test(
            etag="asdfqwerty",
            expected_status_code="304",
            if_none_match='"asdfqwerty"',
            if_modified_since=None,
        )

    def test_none_match_no_quotes_etag_with_extra_spaces(self):
        """Same as test_none_match(), but etag isn't enclosed in double quotes."""
        self._test(
            etag="asdfqwerty   ",
            expected_etag_200="asdfqwerty",
            expected_etag_304='"asdfqwerty"',
            expected_status_code="304",
            if_none_match='"asdfqwerty"',
            if_modified_since=None,
        )

    def test_none_match_empty_etag(self):
        """Same as test_none_match(), but etag isn't enclosed in double quotes and empty."""
        self._test(
            etag='""',
            expected_status_code="304",
            if_none_match='""',
            if_modified_since=None,
        )

    def test_none_match_no_quotes_empty_etag(self):
        """Same as test_none_match(), but etag isn't enclosed in double quotes and empty."""
        self._test(
            etag="",
            expected_etag_200="",
            expected_etag_304='""',
            expected_status_code="304",
            if_none_match='""',
            if_modified_since=None,
        )

    def test_none_match_no_quotes_empty_etag_with_extra_spaces(self):
        self._test(
            etag="  ",
            expected_status_code="304",
            expected_etag_200=" ",
            expected_etag_304='""',
            if_none_match='""',
            if_modified_since=None,
        )

    def test_none_match_weak_srv(self):
        """Same as test_none_match() but server sends weak etag."""
        self._test(
            etag='W/"asdfqwerty"',
            expected_status_code="304",
            if_none_match='"asdfqwerty"',
            if_modified_since=None,
        )

    def test_none_match_weak_clnt(self):
        """Same as test_none_match() but client sends weak etag."""
        self._test(
            etag='"asdfqwerty"',
            expected_status_code="304",
            if_none_match='W/"asdfqwerty"',
            if_modified_since=None,
        )

    def test_none_match_weak_all(self):
        """Same as test_none_match() but both server and client send weak etag."""
        self._test(
            etag='W/"asdfqwerty"',
            expected_status_code="304",
            if_none_match='W/"asdfqwerty"',
            if_modified_since=None,
        )

    def test_none_match_list(self):
        """Same as test_none_match() but client has saved copies of several resources."""
        self._test(
            etag='"asdfqwerty"',
            expected_status_code="304",
            if_none_match='"fsdfds", "asdfqwerty", "sdfrgg"',
            if_modified_since=None,
        )

    def test_none_match_any(self):
        """Same as test_none_match() but client has cached entire world cached."""
        self._test(
            etag='"asdfqwerty"',
            expected_status_code="304",
            if_none_match="*",
            if_modified_since=None,
        )

    def test_none_match_nc_GET(self):
        """Client has not cached resource, send full response."""
        self._test(
            etag='"asdfqwerty"',
            expected_status_code="200",
            if_none_match='"jfgfdgnjdn"',
            if_modified_since=None,
            method="GET",
        )

    def test_none_match_nc_HEAD(self):
        """Client has not cached resource, send full response."""
        self._test(
            etag='"asdfqwerty"',
            expected_status_code="200",
            if_none_match='"jfgfdgnjdn"',
            if_modified_since=None,
            method="HEAD",
        )

    def test_mod_since(self):
        """Client has cached resource, send 304."""
        self._test(
            etag='"asdfqwerty"',
            expected_status_code="304",
            if_none_match=None,
            if_modified_since="Mon, 12 Dec 2016 13:59:39 GMT",
        )

    def test_mod_since_nc(self):
        """Client has not cached resource, send full response."""
        self._test(
            etag='"asdfqwerty"',
            expected_status_code="200",
            if_none_match=None,
            if_modified_since="Mon, 5 Dec 2016 13:59:39 GMT",
        )

    def test_mod_since_nc_with_invalid_date(self):
        """Client has not cached resource, send full response."""
        self._test(
            etag='"asdfqwerty"',
            expected_status_code="200",
            if_none_match=None,
            if_modified_since="invalid date",
        )

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="last_modified",
                response_headers="Date: Mon, 12 Dec 2016 13:59:39 GMT\r\n",
                if_modified_since=HttpMessage.date_time_string,
                expected_status="304",
            ),
            marks.Param(
                name="last_modified_nc",
                response_headers="Date: Mon, 12 Dec 2016 13:59:39 GMT\r\n",
                if_modified_since=lambda: "Mon, 5 Dec 2016 13:59:39 GMT",
                expected_status="200",
            ),
            marks.Param(
                name="last_modified_and_date",
                response_headers="",
                if_modified_since=HttpMessage.date_time_string,
                expected_status="304",
            ),
            marks.Param(
                name="last_modified_and_date_nc",
                response_headers="",
                if_modified_since=lambda: "Mon, 5 Dec 2016 13:59:39 GMT",
                expected_status="200",
            ),
        ]
    )
    def test_response_without(self, name, response_headers, if_modified_since, expected_status):
        self.start_all_services()
        srv = self.get_server("deproxy")
        client = self.get_client("deproxy")

        srv.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Content-Length: 0\r\n"
            + "Server: Deproxy Server\r\n"
            + response_headers
            + "\r\n"
        )

        client.send_request(
            request=client.create_request(method="GET", uri="/page.html", headers=[]),
            expected_status_code="200",
        )
        client.send_request(
            request=client.create_request(
                method="GET", uri="/page.html", headers=[("If-Modified-Since", if_modified_since())]
            ),
            expected_status_code=expected_status,
        )

        self.assertEqual(len(srv.requests), 1, "Server has received unexpected number of requests.")

    def test_correct_none_match_and_modified_since(self):
        """
        Client has cached resource, send 304. 'if_modified_since' ignored.
        RFC 9110 13.1.3
        """
        self._test(
            etag='"asdfqwerty"',
            expected_status_code="304",
            if_none_match='"asdfqwerty"',
            if_modified_since="Mon, 12 Dec 2016 13:59:39 GMT",
        )

    def test_incorrect_none_match_and_correct_modified_since(self):
        """
        Client has no cached resource, send full response. 'if_modified_since' ignored.
        RFC 9110 13.1.3
        """
        self._test(
            etag='"asdfqwerty"',
            expected_status_code="200",
            if_none_match='"jfgfdgnjdn"',
            if_modified_since="Mon, 12 Dec 2016 13:59:39 GMT",
        )


@marks.parameterize_class(
    [
        {"name": "Http", "clients": [DEPROXY_CLIENT]},
        {"name": "H2", "clients": [DEPROXY_CLIENT_H2]},
    ]
)
class TestNotModifiedResponseHeaders(TempestaTest):
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
    cache_methods GET;
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

    def __test_cachable_headers(
        self, header, expected_status_code, date, disable_deproxy_auto_parser
    ):
        """
        The server generating a 304 response MUST generate any of the following header
        fields that would have been sent in a 200 (OK) response to the same request:
        - Content-Location, Date, ETag, and Vary;
        - Cache-Control and Expires;
        RFC 9110 15.4.5
        """
        self.start_all_services()

        srv = self.get_server("deproxy")
        client = self.get_client("deproxy")

        if disable_deproxy_auto_parser:
            self.disable_deproxy_auto_parser()

        srv.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Content-Length: 0\r\n"
            + "Server: Deproxy Server\r\n"
            + f"{header[0]}: {header[1]}\r\n"
            + f"date: {date}\r\n"
            + "\r\n"
        )

        client.send_request(
            request=client.create_request(method="GET", uri="/page.html", headers=[]),
            expected_status_code="200",
        )
        self.assertIn(header, client.last_response.headers.items())
        self.assertIn(("date", date), client.last_response.headers.items())

        client.send_request(
            request=client.create_request(
                method="GET", uri="/page.html", headers=[("If-Modified-Since", date)]
            ),
            expected_status_code=expected_status_code,
        )
        self.assertIn(header, client.last_response.headers.items())
        self.assertIn(("date", date), client.last_response.headers.items())

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="vary",
                header=("vary", "accept-language"),
                expected_status_code="304",
                date=HttpMessage.date_time_string(),
                disable_deproxy_auto_parser=False,
            ),
            marks.Param(
                name="content-location",
                header=("content-location", "/documents/page.html"),
                expected_status_code="304",
                date=HttpMessage.date_time_string(),
                disable_deproxy_auto_parser=False,
            ),
            marks.Param(
                name="expires",
                header=("expires", "Thu, 01 Dec 2102 16:00:00 GMT"),
                expected_status_code="304",
                date=HttpMessage.date_time_string(),
                disable_deproxy_auto_parser=False,
            ),
            marks.Param(
                name="date_invalid",
                header=("expires", "Thu, 01 Dec 2102 16:00:00 GMT"),
                expected_status_code="200",
                date="Thu, 01 Dec 2102 16:00:00 GMT111",
                disable_deproxy_auto_parser=True,
            ),
            marks.Param(
                name="expires_and_date_invalid",
                header=("expires", "Thu, 01 Dec 2102 16:00:00 GMT111"),
                expected_status_code="200",
                date="Thu, 01 Dec 2102 16:00:00 GMT111",
                disable_deproxy_auto_parser=True,
            ),
            marks.Param(
                name="cache-control",
                header=("cache-control", "public"),
                expected_status_code="304",
                date=HttpMessage.date_time_string(),
                disable_deproxy_auto_parser=False,
            ),
            marks.Param(
                name="etag",
                header=("etag", '"etag"'),
                expected_status_code="304",
                date=HttpMessage.date_time_string(),
                disable_deproxy_auto_parser=False,
            ),
        ]
    )
    def test_cachable_headers(
        self, name, header, expected_status_code, date, disable_deproxy_auto_parser
    ):
        self.__test_cachable_headers(
            header, expected_status_code, date, disable_deproxy_auto_parser
        )

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="expires_invalid",
                header=("expires", "Thu, 01 Dec 2102 16:00:00 GMT111"),
                expected_status_code="200",
                date=HttpMessage.date_time_string(),
                disable_deproxy_auto_parser=False,
            ),
        ]
    )
    @unittest.expectedFailure
    def test_cachable_headers_expect_fail(
        self, name, header, expected_status_code, date, disable_deproxy_auto_parser
    ):
        """
        Tempesta FW doesn't check that there is any invalid
        bytes after GMT in the date. So Tempesta FW doesn't
        ignore such header.
        """
        self.__test_cachable_headers(
            header, expected_status_code, date, disable_deproxy_auto_parser
        )

    def test_non_cachable_header(self):
        self.start_all_services()

        srv = self.get_server("deproxy")
        client = self.get_client("deproxy")
        date = HttpMessage.date_time_string()

        srv.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Content-Length: 0\r\n"
            + "Server: Deproxy Server\r\n"
            + f"x-my-hdr: 123\r\n"
            + f"date: {date}\r\n"
            + "\r\n"
        )

        client.send_request(
            request=client.create_request(method="GET", uri="/page.html", headers=[]),
            expected_status_code="200",
        )
        self.assertIn(("x-my-hdr", "123"), client.last_response.headers.items())

        client.send_request(
            request=client.create_request(
                method="GET", uri="/page.html", headers=[("If-Modified-Since", date)]
            ),
            expected_status_code="304",
        )
        self.assertNotIn(("x-my-hdr", "123"), client.last_response.headers.items())
