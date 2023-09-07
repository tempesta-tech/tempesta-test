"""
Tests for correct handling of HTTP/1.1 headers.
"""

from framework import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
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


class TestHost(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + "Date: test\r\n"
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

    def test_different_host_in_uri_and_headers(self):
        self.start_all_services()
        client = self.get_client("deproxy")

        client.send_request(
            request=f"GET http://user@tempesta-tech.com/ HTTP/1.1\r\nHost: localhost\r\n\r\n",
            expected_status_code="200",
        )

    def test_forwarded_and_empty_host_header(self):
        """Host header must be present. Forwarded header does not set host header."""
        self.start_all_services()
        client = self.get_client("deproxy")

        client.send_request(
            request=(
                f"GET http://user@tempesta-tech.com/ HTTP/1.1\r\nForwarded: host=localhost\r\n\r\n"
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
                + "Date: test\r\n"
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
                    + "Date: test\r\n"
                    + "Server: debian\r\n"
                    + f"{'a' * length}: text\r\n"
                    + "Content-Length: 0\r\n\r\n"
                )
                client.send_request(f"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", status_code)

    def test_trailers_in_request(self):
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
                "0\r\n"
                "X-Token: value\r\n\r\n"
            ),
            expected_status_code="200",
        )

        self.assertIn(("X-Token", "value"), server.last_request.trailer.headers)

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


class TestMethods(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + "Date: test\r\n"
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

    """
    Methods known to Tempesta except PURGE it's covered by another tests.
    See tempesta enum tfw_http_meth_t in fw/http.h
    """
    known_methods = [
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

    unknown_methods = [
        "ACL",
        "UPDATEREDIRECTREF",
    ]

    def process(self, methods, leading_crlf=False):
        crlf = "\r\n" if leading_crlf else ""
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        for i, method in enumerate(methods):
            client.make_request(
                request=crlf + method + " / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            )
            client.wait_for_response()
            self.assertEqual(
                client.last_response.status,
                "200",
                f'Wrong status {client.last_response.status} for method "{method}"',
            )
            self.assertEqual(len(client.responses), i + 1, f"Lost response for method {method}")
            self.assertEqual(
                server.last_request.method,
                method,
                f"Wrong method received on server",
            )

    def test_known_methods(self):
        """
        Test correctness of processing all http methods known to Tempesta FW.
        """
        self.start_all_services()
        self.process(self.known_methods)

    def test_known_methods_leading_crlf(self):
        """
        Test correctness of processing all http methods known to Tempesta FW.
        CRLF will be prepended to http request, this leading CRLF must be skipped
        during parsing, method must not contain leading CRLF.
        """
        self.start_all_services()
        self.process(self.known_methods, True)

    def test_unknown_methods(self):
        """
        Test correctness of processing http methods unknown to Tempesta FW.
        """
        self.start_all_services()
        self.process(self.unknown_methods)

    def test_unknown_methods_leading_crlf(self):
        """
        Test correctness of processing http methods unknown to Tempesta FW.
        CRLF will be prepended to http request, this leading CRLF must be skipped
        during parsing, method must not contain leading CRLF.
        """
        self.start_all_services()
        self.process(self.unknown_methods, True)
