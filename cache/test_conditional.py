"""Functional tests of caching different methods."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework.deproxy_client import DeproxyClient
from framework.deproxy_server import StaticDeproxyServer
from framework.tester import TempestaTest
from helpers import tf_cfg
from helpers.deproxy import HttpMessage


class TestConditional(TempestaTest):
    """There are checks for 'if-none-match' and 'if-modified-since' headers in request."""

    tempesta = {
        "config": """
listen 80;

server ${server_ip}:8000;

vhost default {
    proxy_pass default;
}

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

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
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
    ):
        """
        Send GET request and receive 'Etag' header. Repeat request with correct/incorrect
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
            + "<html></html>\r\n",
        )

        if not expected_etag_200:
            expected_etag_200 = etag
        if not expected_etag_304:
            expected_etag_304 = etag

        client.send_request(
            request=(
                "GET /page.html HTTP/1.1\r\n"
                + "Host: {0}\r\n".format(tf_cfg.cfg.get("Client", "hostname"))
                + "Connection: keep-alive\r\n"
                + "Accept: */*\r\n"
                + "\r\n"
            ),
            expected_status_code="200",
        )
        self.assertIn(expected_etag_200, str(client.last_response))

        if if_none_match and if_modified_since:
            option_header = (
                f"if-none-match: {if_none_match}\r\n"
                + f"if-modified-since: {if_modified_since}\r\n"
            )
        elif if_none_match:
            option_header = f"if-none-match: {if_none_match}\r\n"
        elif if_modified_since:
            option_header = f"if-modified-since: {if_modified_since}\r\n"
        else:
            option_header = ""

        client.send_request(
            request=(
                "GET /page.html HTTP/1.1\r\n"
                + "Host: {0}\r\n".format(tf_cfg.cfg.get("Client", "hostname"))
                + "Connection: keep-alive\r\n"
                + "Accept: */*\r\n"
                + option_header
                + "\r\n"
            ),
            expected_status_code=expected_status_code,
        )

        self.assertIn(expected_etag_304, client.last_response.headers["etag"])
        self.assertEqual(len(srv.requests), 1, "Server has received unexpected number of requests.")

    def test_none_match(self):
        """Client has cached resource, send 304."""
        self._test(
            etag='"asdfqwerty"',
            expected_status_code="304",
            if_none_match='"asdfqwerty"',
            if_modified_since=None,
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

    def test_none_match_nc(self):
        """Client has not cached resource, send full response."""
        self._test(
            etag='"asdfqwerty"',
            expected_status_code="200",
            if_none_match='"jfgfdgnjdn"',
            if_modified_since=None,
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
