"""
Tests for correct handling of HTTP/1.1 headers.
"""

from framework import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
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

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.start_all_clients()
        self.assertTrue(self.wait_all_connections(1))

    def test_request_success(self):
        """Test that Tempesta proxies responses with Set-Cookie headers successfully."""
        self.start_all()
        client = self.get_client("deproxy")
        for path in (
            "cookie1",  # single Set-Cookie header
            "cookie2",  # two Set-Cookie headers
            "wordpress-login",  # WordPress response with multiple Set-Cookie headers
        ):
            with self.subTest("GET cookies", path=path):
                client.make_request(f"GET /{path} HTTP/1.1\r\n\r\n")
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

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.start_all_clients()
        self.assertTrue(self.wait_all_connections(1))

    def test_request_cache_del_dup_success(self):
        """
        Test that no kernel panic occur when:
          - cache is on
          - HTTP headers in response from backend are repeated
          - `cache_resp_hdr_del` is used.
        (see Tempesta issue #1691)
        """
        self.start_all()
        client = self.get_client("deproxy")

        client.make_request("GET / HTTP/1.1\r\n\r\n")

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

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections(1))

    def test_small_header_name_accepted(self):
        """Request with small header name length completes successfully."""
        self.start_all()
        client = self.get_client("deproxy")

        for length in range(1, 5):
            header = "X" * length
            client.start()
            with self.subTest(header=header):
                client.make_request("GET / HTTP/1.1\r\n" f"{header}: test\r\n" "\r\n")
                self.assertTrue(client.wait_for_response(timeout=1))
                self.assertEqual(client.last_response.status, "200")
            client.stop()
