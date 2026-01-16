"""
Tests for correct handling of HTTP/1.1 headers.
"""

from framework import deproxy
from test_suite import marks, tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


# Response from the WordPress POST /wp-login.php
wordpress_login_response = """HTTP/1.1 200 OK
Date: Thu, 08 Sep 2022 11:50:34 GMT
Server: Apache/2.4.54 (Debian)
X-Powered-By: PHP/7.4.30
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Cache-Control: no-cache, must-revalidate, max-age=0
Set-Cookie: wordpress_test_cookie=WP%20Cookie%20check; path=/
X-Frame-Options: SAMEORIGIN
Set-Cookie: wordpress_86a9106ae65537651a8e456835b316ab=admin%7C1662810634%7CY5HVGAwBX3g13hZEvGgwSf7fyUY1t5ZaPi2JsH8Fpsa%7C634effa8a901f9b410b6fd18ca0512039ffe2f362a0d70b6d82ff995b7f8be22; path=/wp-content/plugins; HttpOnly
Set-Cookie: wordpress_86a9106ae65537651a8e456835b316ab=admin%7C1662810634%7CY5HVGAwBX3g13hZEvGgwSf7fyUY1t5ZaPi2JsH8Fpsa%7C634effa8a901f9b410b6fd18ca0512039ffe2f362a0d70b6d82ff995b7f8be22; path=/wp-admin; HttpOnly
Set-Cookie: wordpress_logged_in_86a9106ae65537651a8e456835b316ab=admin%7C1662810634%7CY5HVGAwBX3g13hZEvGgwSf7fyUY1t5ZaPi2JsH8Fpsa%7Cd20c220a6974e7c1bdad6eb90b19b37986bbb06ada7bff996b55d0269c077c90; path=/; HttpOnly
Vary: Accept-Encoding
Content-Length: 15
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>"""


class BackendSetCoookie(tester.TempestaTest):
    backends = [
        {
            "id": "set-cookie-1",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n" "Set-Cookie: c1=test1\r\n" "Content-Length: 0\r\n\r\n"
            ),
        },
        {
            "id": "set-cookie-2",
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                "Set-Cookie: c1=test1\r\n"
                "Set-Cookie: c2=test2\r\n"
                "Content-Length: 0\r\n\r\n"
            ),
        },
        {
            "id": "wordpress-login",
            "type": "deproxy",
            "port": "8002",
            "response": "static",
            "response_content": wordpress_login_response,
        },
    ]

    tempesta = {
        "config": """
        listen 80;
        srv_group sg1 { server ${server_ip}:8000; }
        srv_group sg2 { server ${server_ip}:8001; }
        srv_group sg3 { server ${server_ip}:8002; }

        vhost cookie1 { proxy_pass sg1; }  # single cookie
        vhost cookie2 { proxy_pass sg2; }  # two cookie headers
        vhost wordpress-login { proxy_pass sg3; }  # WordPress login response

        http_chain {
          uri == "/cookie1" -> cookie1;
          uri == "/cookie2" -> cookie2;
          uri == "/wordpress-login" -> wordpress-login;
        }
        """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        }
    ]

    def test_request_success(self):
        """Test that Tempesta proxies responses with Set-Cookie headers successfully."""
        self.start_all_services()
        client = self.get_client("deproxy")
        for path in (
            "cookie1",  # single Set-Cookie header
            "cookie2",  # two Set-Cookie headers
            "wordpress-login",  # WordPress response with multiple Set-Cookie headers
        ):
            with self.subTest("GET cookies", path=path):
                client.make_request(f"GET /{path} HTTP/1.1\r\nHost: deproxy\r\n\r\n")
                self.assertTrue(client.wait_for_response(timeout=1))
                self.assertEqual(client.last_response.status, "200")


class RepeatedHeaderCache(tester.TempestaTest):
    backends = [
        {
            "id": "headers",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                "Dup: 1\r\n"  # Header is
                "Dup: 2\r\n"  # repeated
                "Content-Length: 0\r\n\r\n"
            ),
        },
    ]

    tempesta = {
        "config": """
        listen 80;
        cache 1;
        cache_fulfill * *;
        cache_resp_hdr_del No-Such-Header;  # Attempt to delete header
        server ${server_ip}:8000;
        """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        }
    ]

    def test_request_cache_del_dup_success(self):
        """
        Test that no kernel panic occur when:
          - cache is on
          - HTTP headers in response from backend are repeated
          - `cache_resp_hdr_del` is used.
        (see Tempesta issue #1691)
        """
        self.start_all_services()
        client = self.get_client("deproxy")

        client.make_request("GET / HTTP/1.1\r\nHost: deproxy\r\n\r\n")

        self.assertTrue(client.wait_for_response(timeout=1))
        self.assertEqual(client.last_response.status, "200")


class TestSmallHeader(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": ("HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n"),
        },
    ]

    tempesta = {
        "config": """
        listen 80;
        server ${server_ip}:8000;
        cache 0;
        """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        }
    ]

    def test_small_header_name_accepted(self):
        """Request with small header name length completes successfully."""
        self.start_all_services()
        client = self.get_client("deproxy")

        for length in range(1, 5):
            header = "X" * length
            client.start()
            with self.subTest(header=header):
                client.make_request(f"GET / HTTP/1.1\r\nHost: deproxy\r\n{header}: test\r\n\r\n")
                self.assertTrue(client.wait_for_response(timeout=1))
                self.assertEqual(client.last_response.status, "200")
            client.stop()


class TestHostBase(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + f"Date: {deproxy.HttpMessage.date_time_string()}\r\n"
                + "Server: debian\r\n"
                + "Content-Length: 0\r\n\r\n"
            ),
        }
    ]

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]


class TestHost(TestHostBase):
    tempesta = {
        "config": """
            listen 80;
            server ${server_ip}:8000;
            
            frang_limits {http_strict_host_checking false;}
            block_action attack reply;
            block_action error reply;
        """
    }

    def test_host_missing(self):
        self.start_all_services()
        client = self.get_client("deproxy")

        client.send_request(
            request=f"GET / HTTP/1.1\r\n\r\n",
            expected_status_code="400",
        )

    def test_host_header_empty(self):
        self.start_all_services()
        client = self.get_client("deproxy")

        client.send_request(
            request=f"GET / HTTP/1.1\r\nHost:\r\n\r\n",
            expected_status_code="400",
        )

    def test_host_header_ok(self):
        self.start_all_services()
        client = self.get_client("deproxy")

        client.send_request(
            request=f"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            expected_status_code="200",
        )

    def test_host_in_uri_without_host_header(self):
        self.start_all_services()
        client = self.get_client("deproxy")

        client.send_request(
            request=f"GET http://user@tempesta-tech.com/ HTTP/1.1\r\n\r\n",
            expected_status_code="400",
        )

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="full_path",
                uri_host="tempesta-tech.com",
                uri_path="/path/to/file",
            ),
            marks.Param(
                name="empty_path",
                uri_host="tempesta-tech.com",
                uri_path="",
            ),
            marks.Param(
                name="default_path",
                uri_host="tempesta-tech.com",
                uri_path="/",
            ),
        ]
    )
    def test_forward_absolute_uri(self, name, uri_host, uri_path):
        """
        Verify correctness of forwarding a request with absolute URI.
        During forwarding Tempesta modifies request's URI transforming
        to non absolute form. Therefore on upstream always expected non
        absolute URI.
        """

        self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        client.send_request(
            request=f"GET http://{uri_host}{uri_path} HTTP/1.1\r\nHost: localhost\r\n\r\n",
            expected_status_code="200",
        )

        # non absolute uri is expected on upstream.
        expected_uri = "/" if uri_path == "" else uri_path
        self.assertEqual(server.last_request.uri, expected_uri)
        self.assertEqual(server.last_request.headers.get("host"), uri_host)

    def test_forwarded_and_empty_host_header(self):
        """Host header must be present. Forwarded header does not set host header."""
        self.start_all_services()
        client = self.get_client("deproxy")

        client.send_request(
            request=(
                f"GET http://tempesta-tech.com/ HTTP/1.1\r\nForwarded: host=localhost\r\n\r\n"
            ),
            expected_status_code="400",
        )


class TestHeadersParsing(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + f"Date: {deproxy.HttpMessage.date_time_string()}\r\n"
                + "Server: debian\r\n"
                + "Content-Length: 0\r\n\r\n"
            ),
        }
    ]

    tempesta = {
        "config": """
            listen 80;
            server ${server_ip}:8000;

            block_action attack reply;
            block_action error reply;
            cache 0;
        """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    def test_long_header_name_in_request(self):
        """Max length for header name - 1024. See fw/http_parser.c HTTP_MAX_HDR_NAME_LEN"""
        for length, status_code in ((1023, "200"), (1024, "200"), (1025, "400")):
            with self.subTest(length=length, status_code=status_code):
                self.start_all_services()

                client = self.get_client("deproxy")
                client.send_request(
                    f"GET / HTTP/1.1\r\nHost: localhost\r\n{'a' * length}: text\r\n\r\n",
                    status_code,
                )

    def test_long_header_name_in_response(self):
        """Max length for header name - 1024. See fw/http_parser.c HTTP_MAX_HDR_NAME_LEN"""
        for length, status_code in ((1023, "200"), (1024, "200"), (1025, "502")):
            with self.subTest(length=length, status_code=status_code):
                self.start_all_services()

                client = self.get_client("deproxy")
                server = self.get_server("deproxy")
                server.set_response(
                    "HTTP/1.1 200 OK\r\n"
                    + f"Date: {deproxy.HttpMessage.date_time_string()}\r\n"
                    + "Server: debian\r\n"
                    + f"{'a' * length}: text\r\n"
                    + "Content-Length: 0\r\n\r\n"
                )
                client.send_request(f"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", status_code)

    @marks.Parameterize.expand(
        [
            marks.Param(name="trailer_GET", method="GET"),
            marks.Param(name="trailer_HEAD", method="HEAD"),
        ]
    )
    def test_trailers_in_request(self, name, method):
        self.start_all_services()

        client = self.get_client("deproxy")
        client.send_request(
            request=(
                f"{method} / HTTP/1.1\r\n"
                + "Host: localhost\r\n"
                + "Connection: HbpHeader1 HbpHeader2\r\n"
                + "Content-type: text/html\r\n"
                + "Transfer-Encoding: chunked\r\n"
                + "Trailer: X-Token1 X-Token2\r\n\r\n"
                + "10\r\n"
                + "abcdefghijklmnop\r\n"
                + "0\r\n"
                + "X-Token1: value1\r\n"
                + "X-Token2: value2\r\n\r\n"
            ),
            expected_status_code="400",
        )

    def test_invalid_trailers_in_request(self):
        self.start_all_services()

        client = self.get_client("deproxy")
        client.send_request(
            request=(
                "POST / HTTP/1.1\r\n"
                + "Host: localhost\r\n"
                + "Connection: HbpHeader1 HbpHeader2\r\n"
                + "Content-type: text/html\r\n"
                + "Transfer-Encoding: chunked\r\n"
                + f"Trailer: X-Token1 cache-control X-Token2\r\n\r\n"
                + "10\r\n"
                + "abcdefghijklmnop\r\n"
                + "0\r\n"
                + "X-Token1: value1\r\n"
                + "cache-control: no-cache\r\n"
                + "X-Token2: value2\r\n\r\n"
            ),
            expected_status_code="400",
        )

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="trailer_POST",
                tr1="X-Token1",
                tr1_val="value1",
                tr2="X-Token2",
                tr2_val="value2",
                expected_status_code="200",
            ),
            marks.Param(
                name="trailer_mix_POST_keep_alive",
                tr1="X-Token1",
                tr1_val="value1",
                tr2="Keep-Alive",
                tr2_val="timeout=5, max=20",
                expected_status_code="400",
            ),
            marks.Param(
                name="trailer_mix_POST_upgrade",
                tr1="X-Token1",
                tr1_val="value1",
                tr2="Upgrade",
                tr2_val="websocket",
                expected_status_code="400",
            ),
            marks.Param(
                name="trailer_mix_POST_transfer_encoding",
                tr1="X-Token1",
                tr1_val="value1",
                tr2="Transfer-Encoding",
                tr2_val="chunked",
                expected_status_code="400",
            ),
            marks.Param(
                name="trailer_hbp_from_connection_POST",
                tr1="HbpHeader1",
                tr1_val="value1",
                tr2="HbpHeader2",
                tr2_val="value2",
                expected_status_code="400",
            ),
        ]
    )
    def test_trailers_in_request(self, name, tr1, tr1_val, tr2, tr2_val, expected_status_code):
        self.start_all_services()
        # self.disable_deproxy_auto_parser()

        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        client.send_request(
            request=(
                "POST / HTTP/1.1\r\n"
                + "Host: localhost\r\n"
                + "Connection: HbpHeader1 HbpHeader2\r\n"
                + "Content-type: text/html\r\n"
                + "Transfer-Encoding: chunked\r\n"
                + f"Trailer: {tr1} {tr2}\r\n\r\n"
                + "10\r\n"
                + "abcdefghijklmnop\r\n"
                + "0\r\n"
                + f"{tr1}: {tr1_val}\r\n"
                + f"{tr2}: {tr2_val}\r\n\r\n"
            ),
            expected_status_code=expected_status_code,
        )

        if expected_status_code != "200":
            return

        self.assertIsNone(server.last_request.headers.get("trailer"))
        for tr, tr_val in [(tr1, tr1_val), (tr2, tr2_val)]:
            self.assertEqual(
                server.last_request.trailer.get(tr),
                tr_val,
                "Moved trailer header value mismatch the original one",
            )

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="no_hbp_GET",
                tr1="X-Token1",
                tr1_val="value1",
                tr2="X-Token2",
                tr2_val="value2",
                expected_status_code="200",
            ),
            marks.Param(
                name="hbp_GET",
                tr1="Connection",
                tr1_val="keep-alive",
                tr2="Keep-Alive",
                tr2_val="timeout=5, max=100",
                expected_status_code="502",
            ),
            marks.Param(
                name="mix_GET_keep_alive",
                tr1="X-Token1",
                tr1_val="value1",
                tr2="Connection",
                tr2_val="keep-alive",
                expected_status_code="502",
            ),
            marks.Param(
                name="mix_GET_upgrade",
                tr1="X-Token1",
                tr1_val="value1",
                tr2="Upgrade",
                tr2_val="websocket",
                expected_status_code="502",
            ),
            marks.Param(
                name="mix_GET_transfer_encoding",
                tr1="X-Token1",
                tr1_val="value1",
                tr2="Transfer-Encoding",
                tr2_val="chunked",
                expected_status_code="502",
            ),
            marks.Param(
                name="mix_GET_proxy_connection",
                tr1="X-Token1",
                tr1_val="value1",
                tr2="Proxy-Connection",
                tr2_val="keep-alive",
                expected_status_code="502",
            ),
            marks.Param(
                name="hbp_from_connection_GET",
                tr1="HbpHeader1",
                tr1_val="value1",
                tr2="HbpHeader2",
                tr2_val="value2",
                expected_status_code="502",
            ),
        ]
    )
    def test_trailers_in_response_get(self, name, tr1, tr1_val, tr2, tr2_val, expected_status_code):
        self.start_all_services()

        response = (
            "HTTP/1.1 200 OK\r\n"
            + "Content-type: text/html\r\n"
            + "Connection: HbpHeader1 HbpHeader2\r\n"
            + f"Last-Modified: {deproxy.HttpMessage.date_time_string()}\r\n"
            + f"Date: {deproxy.HttpMessage.date_time_string()}\r\n"
            + "Server: Deproxy Server\r\n"
            + "Transfer-Encoding: chunked\r\n"
            + f"Trailer: {tr1} {tr2}\r\n\r\n"
            + "10\r\n"
            + "abcdefghijklmnop\r\n"
            + "0\r\n"
            + f"{tr1}: {tr1_val}\r\n"
            + f"{tr2}: {tr2_val}\r\n\r\n"
        )

        server = self.get_server("deproxy")
        server.set_response(response)

        client = self.get_client("deproxy")
        request = client.create_request(method="GET", headers=[])
        client.send_request(request, expected_status_code)

        if expected_status_code != "200":
            return

        for tr, tr_val in [(tr1, tr1_val), (tr2, tr2_val)]:
            self.assertEqual(
                client.last_response.trailer.get(tr),
                tr_val,
                "Moved trailer header value mismatch the original one",
            )

        self.assertEqual(client.last_response.headers.get("Transfer-Encoding"), "chunked")
        self.assertIsNone(client.last_response.headers.get("Trailer"))
        self.assertIsNone(client.last_response.headers.get(tr1))
        self.assertIsNone(client.last_response.headers.get(tr2))

    @marks.Parameterize.expand(
        [
            marks.Param(name="no_hbp_HEAD", tr1="X-Token1", tr2="X-Token2"),
            marks.Param(name="hbp_HEAD", tr1="Connection", tr2="Keep-Alive"),
            marks.Param(name="mix_HEAD", tr1="Connection", tr2="X-Token1"),
            marks.Param(name="hbp_from_connection_HEAD", tr1="HbpHeader1", tr2="HbpHeader2"),
        ]
    )
    def test_trailers_in_response_head(self, name, tr1, tr2):
        self.start_all_services()

        response = (
            "HTTP/1.1 200 OK\r\n"
            + "Content-type: text/html\r\n"
            + "Connection: HbpHeader1 HbpHeader2\r\n"
            + f"Last-Modified: {deproxy.HttpMessage.date_time_string()}\r\n"
            + f"Date: {deproxy.HttpMessage.date_time_string()}\r\n"
            + "Server: Deproxy Server\r\n"
            + "Transfer-Encoding: chunked\r\n"
            + f"Trailer: {tr1} {tr2}\r\n\r\n"
        )

        server = self.get_server("deproxy")
        server.set_response(response)

        client = self.get_client("deproxy")
        request = client.create_request(method="HEAD", headers=[])
        client.send_request(request, "200")

        self.assertEqual(client.last_response.headers.get("Transfer-Encoding"), "chunked")
        for tr in (tr1, tr2):
            self.assertIsNone(client.last_response.trailer.get(tr))
            self.assertIsNone(client.last_response.headers.get(tr))

    def test_without_trailers_in_request(self):
        self.start_all_services()

        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        client.send_request(
            request=(
                "POST / HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "Content-type: text/html\r\n"
                "Transfer-Encoding: chunked\r\n"
                "Trailers: X-Token\r\n\r\n"
                "10\r\n"
                "abcdefghijklmnop\r\n"
                "0\r\n\r\n"
            ),
            expected_status_code="200",
        )

        self.assertNotIn(("X-Token", "value"), server.last_request.trailer.headers)

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="empty_body",
                response="HTTP/1.1 200 OK\n"
                + "Transfer-Encoding: chunked\n"
                + "Trailer: X-Token\r\n\r\n"
                + "0\r\n"
                + "Server: deproxy\r\n"
                + "X-Token: value\r\n\r\n",
            ),
            marks.Param(
                name="not_empty_body",
                response="HTTP/1.1 200 OK\n"
                + "Transfer-Encoding: chunked\n"
                + "Trailer: X-Token\r\n\r\n"
                + "10\r\n"
                + "abcdefghijklmnop\r\n"
                + "0\r\n"
                + "Server: deproxy\r\n"
                + "X-Token: value\r\n\r\n",
            ),
        ]
    )
    def test_server_in_trailers_response(self, name, response):
        self.start_all_services()
        server = self.get_server("deproxy")
        server.set_response(response)

        client = self.get_client("deproxy")
        client.send_request(f"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", "502")

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="empty_body",
                response="HTTP/1.1 200 OK\n"
                + "Transfer-Encoding: chunked\n"
                + "Trailer: X-Token\r\n\r\n"
                + "0\r\n"
                + "X-Token: value\r\n\r\n",
            ),
            marks.Param(
                name="not_empty_body",
                response="HTTP/1.1 200 OK\n"
                + "Transfer-Encoding: chunked\n"
                + "Trailer: X-Token\r\n\r\n"
                + "10\r\n"
                + "abcdefghijklmnop\r\n"
                + "0\r\n"
                + "X-Token: value\r\n\r\n",
            ),
        ]
    )
    def test_trailers_in_response_simple(self, name, response):
        self.start_all_services()
        server = self.get_server("deproxy")
        server.set_response(response)

        client = self.get_client("deproxy")
        client.send_request(f"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", "200")
        self.assertIsNone(client.last_response.headers.get("Trailer"))
        self.assertIsNone(client.last_response.headers.get("X-Token"))
        self.assertEqual(client.last_response.headers.get("Transfer-Encoding"), "chunked")
        self.assertIsNotNone(client.last_response.trailer.get("X-Token"))

    @marks.Parameterize.expand(
        [
            marks.Param(name="cache_control", tr="cache-control", tr_val="no-cache"),
            marks.Param(name="date", tr="date", tr_val="Mon, 12 Dec 2016 13:59:39 GMT"),
            marks.Param(name="expires", tr="expires", tr_val="Thu, 01 Dec 2102 16:00:00 GMT"),
            marks.Param(
                name="last_modified", tr="last-modified", tr_val="Mon, 12 Dec 2016 13:59:39 GMT"
            ),
            marks.Param(name="vary", tr="vary", tr_val="accept"),
        ]
    )
    def test_invalid_trailers_in_response(self, name, tr, tr_val):
        self.start_all_services()
        server = self.get_server("deproxy")
        server.set_response(
            "HTTP/1.1 200 OK\n"
            + "Transfer-Encoding: chunked\n"
            + f"Trailer: X-Token {tr}\r\n\r\n"
            + "0\r\n"
            + "X-Token: value\r\n"
            + f"{tr}: {tr_val}\r\n\r\n",
        )

        client = self.get_client("deproxy")
        client.send_request(f"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", "502")


class TestHeadersBlockedByMaxHeaderListSize(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + f"Date: {deproxy.HttpMessage.date_time_string()}\r\n"
                + "Server: debian\r\n"
                + "Content-Length: 0\r\n\r\n"
            ),
        }
    ]

    tempesta = {
        "config": """
            listen 80;
            server ${server_ip}:8000;

            http_max_header_list_size 23;
            block_action attack reply;
            block_action error reply;
        """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    def test_blocked_by_max_headers_count(self):
        """
        Total header length is 24 bytes, greater then 23 bytes.
        Host: localhost (15 bytes)
        'a': aaaa (9 bytes)
        """
        self.start_all_services()
        client = self.get_client("deproxy")

        client.send_request(
            request=f"GET / HTTP/1.1\r\nHost: localhost\r\n'a': aaaa\r\n\r\n",
            expected_status_code="403",
        )

    def test_not_blocked_by_max_headers_count(self):
        """
        Total header length is 23 bytes, not greater then 23 bytes.
        Host: localhost (15 bytes)
        'a': aaa (8 bytes)
        """
        self.start_all_services()
        client = self.get_client("deproxy")

        client.send_request(
            request=f"GET / HTTP/1.1\r\nHost: localhost\r\n'a': aaa\r\n\r\n",
            expected_status_code="200",
        )


class TestHostWithCache(TestHostBase):
    tempesta = {
        "config": """
            listen 80;

            server ${server_ip}:8000;

            vhost good {
                frang_limits {
                    http_strict_host_checking false;
                }
                proxy_pass default;
            }

            frang_limits {http_strict_host_checking false;}
            block_action attack reply;
            block_action error reply;

            cache 2;
            cache_fulfill * *;

            http_chain {
                host == "bad.com" -> block;
                -> good;
            }
        """
    }

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="1",
                request=f"GET http://user@tempesta-tech.com/ HTTP/1.1\r\nHost: localhost\r\n\r\n",
                expected_status_code="400",
            ),
            marks.Param(
                name="2",
                request=f"GET http://user@-x/ HTTP/1.1\r\nHost: localhost\r\n\r\n",
                expected_status_code="400",
            ),
            marks.Param(
                name="3",
                request=f"GET http://user@/ HTTP/1.1\r\nHost: localhost\r\n\r\n",
                expected_status_code="400",
            ),
            marks.Param(
                name="4",
                request=f"GET http://tempesta-tech.com/ HTTP/1.1\r\nHost: bad.com\r\n\r\n",
                expected_status_code="200",
            ),
            marks.Param(
                name="5",
                request=f"GET http://user@:333/ HTTP/1.1\r\nHost: localhost\r\n\r\n",
                expected_status_code="400",
            ),
            marks.Param(
                name="6",
                request=f"GET http://user@:/url/ HTTP/1.1\r\nHost: localhost\r\n\r\n",
                expected_status_code="400",
            ),
            marks.Param(
                name="7",
                request=f"GET http://user@: HTTP/1.1\r\nHost: localhost\r\n\r\n",
                expected_status_code="400",
            ),
            marks.Param(
                name="8",
                request=f"GET http://tempesta-tech.com: HTTP/1.1\r\nHost: localhost\r\n\r\n",
                expected_status_code="400",
            ),
            marks.Param(
                name="9",
                request=f"GET http://tempesta-tech.com:/ HTTP/1.1\r\nHost: localhost\r\n\r\n",
                expected_status_code="400",
            ),
            marks.Param(
                name="10",
                request=f"GET http:///path HTTP/1.1\r\nHost: localhost\r\n\r\n",
                expected_status_code="400",
            ),
            marks.Param(
                name="11",
                request=f"GET http://user@/path HTTP/1.1\r\nHost: localhost\r\n\r\n",
                expected_status_code="400",
            ),
            marks.Param(
                name="12",
                request=f"GET http://:443 HTTP/1.1\r\nHost: localhost\r\n\r\n",
                expected_status_code="400",
            ),
            marks.Param(
                name="13",
                request=f"GET http:///path HTTP/1.1\r\nHost: \r\n\r\n",
                expected_status_code="400",
            ),
            marks.Param(
                name="14",
                request=f"GET http://localhost:443 HTTP/1.1\r\nHost: localhost\r\n\r\n",
                expected_status_code="200",
            ),
            marks.Param(
                name="15",
                request=f"GET http://localhost HTTP/1.1\r\nHost: localhost\r\n\r\n",
                expected_status_code="200",
            ),
        ]
    )
    def test_different_host_in_uri_and_headers(self, name, request, expected_status_code):
        self.start_all_services()
        client = self.get_client("deproxy")
        srv = self.get_server("deproxy")

        client.send_request(
            request=request,
            expected_status_code=expected_status_code,
        )
        self.assertNotIn("age", client.last_response.headers)

        if expected_status_code == "200":
            client.send_request(
                request=request,
                expected_status_code=expected_status_code,
            )
            self.assertIn("age", client.last_response.headers)


@marks.parameterize_class(
    [
        {"name": "MethodHEAD", "method": "HEAD", "statuses": [200]},
        {"name": "MethodGET", "method": "GET", "statuses": [200, 302, 304, 400, 401, 404, 500]},
        {
            "name": "MethodPOST",
            "method": "POST",
            "statuses": [200, 201, 302, 304, 400, 401, 404, 500],
        },
        {
            "name": "MethodDELETE",
            "method": "DELETE",
            "statuses": [200, 201, 302, 304, 400, 401, 404, 500],
        },
        {
            "name": "MethodPATCH",
            "method": "PATCH",
            "statuses": [200, 201, 302, 304, 400, 401, 404, 500],
        },
        {
            "name": "MethodPUT",
            "method": "PUT",
            "statuses": [200, 201, 302, 304, 400, 401, 404, 500],
        },
    ]
)
class TestNoContentLengthInMethod(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
        }
    ]

    tempesta = {
        "config": """
            listen 443 proto=https;
            access_log dmesg;
            
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;
            
            frang_limits {http_methods OPTIONS HEAD GET PUT POST PUT PATCH DELETE;}
            server ${server_ip}:8000;
        """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]
    method: str = None
    statuses: list[int] = None

    @property
    def statuses_description(self) -> dict[int, str]:
        return {
            200: "OK",
            201: "Created",
            302: "Found",
            304: "Not Modified",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error",
        }

    def test_request_success(self):
        self.start_all_services()
        self.disable_deproxy_auto_parser()

        server = self.get_server("deproxy")
        client = self.get_client("deproxy")
        client.start()

        for status in self.statuses:
            with self.subTest(status=status):
                server.set_response(
                    f"HTTP/1.1 {status} {self.statuses_description[status]}\r\n"
                    "Server: debian\r\n"
                    "Content-Length: 0\r\n\r\n\r\n"
                )

                client.send_request(
                    request=client.create_request(method=self.method, headers=[]),
                    expected_status_code=str(status),
                )

                self.assertEqual(
                    client.last_response.headers["content-length"],
                    "0",
                    msg=f"Tempesta should proxy the Content-Length header for the "
                    f"`{self.method} {status} {self.statuses_description[status]}` status code also",
                )


@marks.parameterize_class(
    [
        {
            "name": "POST",
            "method": "POST",
        },
        {
            "name": "PUT",
            "method": "PUT",
        },
        {
            "name": "PATCH",
            "method": "PATCH",
        },
        {
            "name": "DELETE",
            "method": "DELETE",
        },
    ]
)
class TestContentTypeWithEmptyBody(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                "Server: debian\r\n"
                "Content-Length: 0\r\n"
                "Content-Type: text/html; charset=utf-8\r\n\r\n\r\n"
            ),
        }
    ]

    tempesta = {
        "config": """
            listen 443 proto=https;
            access_log dmesg;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;

            frang_limits {http_methods OPTIONS HEAD GET PUT POST PUT PATCH DELETE;}
            server ${server_ip}:8000;
        """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]
    method: str = None

    def test_request_success(self):
        self.start_all_services()
        client = self.get_client("deproxy")
        client.send_request(
            request=client.create_request(method=self.method, headers=[]),
            expected_status_code="200",
        )
        self.assertEqual(
            client.last_response.headers["content-type"],
            "text/html; charset=utf-8",
            msg="Tempesta should proxy the Content-Type header for the CRUD method with empty body also",
        )


"""
Methods known to Tempesta except PURGE it's covered by another tests.
See tempesta enum tfw_http_meth_t in fw/http.h
"""
KNOWN_METHODS = [
    "COPY",
    "DELETE",
    "GET",
    "HEAD",
    "LOCK",
    "MKCOL",
    "MOVE",
    "OPTIONS",
    "PATCH",
    "POST",
    "PROPFIND",
    "PROPPATCH",
    "PUT",
    "TRACE",
    "UNLOCK",
]

UNKNOWN_METHODS = [
    "ACL",
    "UPDATEREDIRECTREF",
]


class TestMethods(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + f"Date: {deproxy.HttpMessage.date_time_string()}\r\n"
                + "Server: debian\r\n"
                + "Content-Length: 0\r\n\r\n"
            ),
        }
    ]

    tempesta = {
        "config": """
            listen 80;
            server ${server_ip}:8000;
            block_action attack reply;
            block_action error reply;
            frang_limits {
                http_methods copy delete get head lock mkcol move options patch post propfind proppatch put trace unlock unknown;
            }
        """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    @marks.Parameterize.expand(
        [
            marks.Param(name="known_methods", methods=KNOWN_METHODS, crlf=""),
            marks.Param(name="known_methods_leading_crlf", methods=KNOWN_METHODS, crlf="\r\n"),
            marks.Param(name="unknown_methods", methods=UNKNOWN_METHODS, crlf=""),
            marks.Param(name="unknown_methods_leading_crlf", methods=UNKNOWN_METHODS, crlf="\r\n"),
        ]
    )
    def test(self, name, methods, crlf):
        self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        for i, method in enumerate(methods):
            client.send_request(
                request=f"{crlf}{method} / HTTP/1.1\r\nHost: localhost\r\n\r\n",
                expected_status_code="200",
            )
            self.assertEqual(
                server.last_request.method,
                method,
                f"Wrong method received on server",
            )
