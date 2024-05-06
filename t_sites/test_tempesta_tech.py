"""The basic tests for tempesta-tech.com with TempestaFW."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"


import run_config
from framework import tester
from framework.curl_client import CurlClient, CurlResponse
from framework.mixins import NetfilterMarkMixin


class TestTempestaTechSite(NetfilterMarkMixin, tester.TempestaTest):
    backends = [
        {"id": "tempesta_tech_site", "type": "lxc", "external_port": "8000"},
    ]

    clients = [
        {
            "id": "get",
            "type": "curl",
            "http2": True,
        },
        {
            "id": "get_authenticated",
            "type": "curl",
            "http2": True,
            "load_cookies": True,
        },
        {
            "id": "login",
            "type": "curl",
            "http2": True,
            "save_cookies": True,
            "uri": "/wp-login.php",
        },
        {
            "id": "purge_cache",
            "type": "curl",
            "http2": True,
            # Set max-time to prevent hang caused by Tempesta FW #1692
            "cmd_args": "--request PURGE --max-time 1",
        },
        {
            "id": "nghttp",
            "type": "external",
            "binary": "nghttp",
            "cmd_args": (
                " --no-verify-peer"
                " --get-assets"
                " --null-out"
                " --header 'Cache-Control: no-cache'"
                " https://${tempesta_ip}"
            ),
        },
    ]

    tempesta = {
        "config": """
            listen 192.168.122.1:443 proto=h2;

            cache 2;
            cache_fulfill * *;
            cache_methods GET HEAD;
            cache_purge;
            # Allow purging from the containers (upstream), localhost (VM) and the host.
            cache_purge_acl ${server_ip} 127.0.0.1;

            access_log on;

            frang_limits {
                request_rate 200;
                http_method_override_allowed true;
                http_methods post put get purge;
            }

            block_action attack reply;
            block_action error reply;

            # Make WordPress to work over TLS.
            # See https://tempesta-tech.com/knowledge-base/WordPress-tips-and-tricks/
            req_hdr_add X-Forwarded-Proto "https";

            resp_hdr_set Strict-Transport-Security "max-age=31536000; includeSubDomains";

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;

            srv_group default {
                    server ${server_ip}:8000;

            }
            vhost default {
                    tls_match_any_server_name;
                    proxy_pass default;
            }

            http_chain {
                # Redirect old URLs from the old static website
                uri == "/index"		-> 301 = /;
                uri == "/development-services" -> 301 = /network-security-performance-analysis;

                # Proably outdated redirects
                uri == "/index.html"	-> 301 = /;
                uri == "/services"	-> 301 = /development-services;
                uri == "/services.html"	-> 301 = /development-services;
                uri == "/c++-services"	-> 301 = /development-services;
                uri == "/company.html"	-> 301 = /company;
                uri == "/blog/fast-programming-languages-c-c++-rust-assembly" -> 301 = /blog/fast-programming-languages-c-cpp-rust-assembly;

                    -> default;
            }
        """
    }

    def get_response(self, client: CurlClient) -> CurlResponse:
        client.headers["Host"] = "tempesta-tech.com"
        client.start()
        self.wait_while_busy(client)
        client.stop()
        return client.last_response

    @staticmethod
    def check_cached_headers(headers):
        """Return True if headers are from cached response."""
        return "age" in headers

    def login(self, load_cookies=False):
        client: CurlClient = self.get_client("login")
        client.clear_cookies()
        client.data = f"log={run_config.WEBSITE_USER}&pwd={run_config.WEBSITE_PASSWORD}"
        client.load_cookies = load_cookies

        response = self.get_response(client)
        self.assertEqual(response.status, 302)
        # Login page set multiple cookies
        self.assertGreater(len(response.multi_headers["set-cookie"]), 1)
        self.assertIn("wp-admin", response.headers["location"])
        self.assertFalse(self.check_cached_headers(response.headers))
        return response

    def purge_cache(self, uri, fetch=False):
        """
        Purge the cached resource.
        Immediately fetch a new version of the resource, if `fetch` is set.
        """
        client = self.get_client("purge_cache")
        client.set_uri(uri)
        client.headers = {"X-Tempesta-Cache": "get"} if fetch else {}
        response = self.get_response(client)
        self.assertEqual(response.status, 200)

    def test_get_resource(self):
        self.start_all_services(client=False)
        client = self.get_client("get")

        for uri, expected_code in [
            ("/license.txt", 200),
            (
                "/wp-content/uploads/2023/10/tfw_wp_http2-150x150.png",
                200,
            ),  # small image
            (
                "/wp-content/uploads/2023/10/tfw_wp_http2-1536x981.png",
                200,
            ),  # large image
            ("/", 200),  # index
            ("/knowledge-base/DDoS-mitigation/", 200),  # blog post
            ("/404-absolutely/doesnt-exist", 404),
        ]:
            with self.subTest("GET", uri=uri):
                client.set_uri(uri)
                response = self.get_response(client)
                self.assertEqual(response.status, expected_code, response)
                self.assertFalse(response.stderr)
                length = response.headers.get("content-length")
                if length:
                    self.assertEqual(len(response.stdout_raw), int(length))
                self.assertNotIn("age", response.headers)

    def test_page_cached(self):
        uri = "/license.txt"  # Main

        self.start_all_services(client=False)
        client = self.get_client("get")
        client.set_uri(uri)

        with self.subTest("First request, expect non-cached response"):
            response = self.get_response(client)
            self.assertEqual(response.status, 200)
            self.assertFalse(
                self.check_cached_headers(response.headers),
                f"Response headers: {response.headers}",
            )

        with self.subTest("Second request, expect cached response"):
            response = self.get_response(client)
            self.assertEqual(response.status, 200)
            self.assertTrue(
                self.check_cached_headers(response.headers),
                f"Response headers: {response.headers}",
            )

        with self.subTest("Third request, expect non-cached response after cache purge"):
            self.purge_cache(uri)
            response = self.get_response(client)
            self.assertEqual(response.status, 200)
            self.assertFalse(
                self.check_cached_headers(response.headers),
                f"Response headers: {response.headers}",
            )

    def test_auth_not_cached(self):
        """Authorisation requests must not be cached."""
        self.start_all_services(client=False)
        for i, load_cookies in enumerate((False, True, True), 1):
            with self.subTest("Login attempt", i=i, load_cookies=load_cookies):
                response = self.login(load_cookies=load_cookies)
                self.assertEqual(
                    self.check_cached_headers(response.headers),
                    False,
                    f"Response headers: {response.headers}",
                )

    def test_blog_post_cached(self):
        self.start_all_services(client=False)

        client = self.get_client("get")
        client.set_uri("/blog/cdn-non-hierarchical-caching/")
        # Check that the first response is not from the cache,
        # and subsequent ones are from the cache
        for i, cached in enumerate([False, True, True], 1):
            with self.subTest("Get blog post", i=i, expect_cached=cached):
                response = self.get_response(client)
                self.assertEqual(response.status, 200)
                self.assertFalse(response.stderr)
                self.assertTrue(response.stdout.endswith("</html>"))
                self.assertGreater(len(response.stdout), 65000, len(response.stdout))
                length = response.headers.get("content-length")
                if length:
                    self.assertEqual(len(response.stdout_raw), int(length))
                elif cached:
                    raise Exception("No Content-Length for cached response", response.headers)
                self.assertEqual(
                    self.check_cached_headers(response.headers),
                    cached,
                    f"Response headers: {response.headers}",
                )

    def test_blog_post_not_cached_for_authenticated_user(self):
        self.start_all_services(client=False)
        self.login()
        client = self.get_client("get_authenticated")
        client.set_uri("/blog/cdn-non-hierarchical-caching/")
        for i in range(3):
            with self.subTest("Get blog post", i=i):
                response = self.get_response(client)
                self.assertEqual(response.status, 200)
                self.assertFalse(response.stderr)
                self.assertFalse(self.check_cached_headers(response.headers))

    def test_get_resource_with_assets(self):
        self.start_all_services(client=False)
        client = self.get_client("nghttp")
        cmd_args = client.options[0]

        curl = self.get_client("get")
        for uri in [
            "/license.txt",  # small file
            "/",  # index
            "/network-security-performance-analysis/",
            "/blog/cdn-non-hierarchical-caching/",  # blog post
            "/blog/nginx-tail-latency/",  # page with a multiple images
        ]:
            with self.subTest("GET", uri=uri):
                curl.set_uri(uri)
                response = self.get_response(curl)
                self.assertEqual(response.status, 200, response)

                client.options = [cmd_args + uri]
                client.start()
                self.wait_while_busy(client)
                client.stop()
                self.assertNotIn("Some requests were not processed", client.response_msg)
                self.assertFalse(client.response_msg)

    def test_get_admin_resource_with_assets(self):
        self.start_all_services(client=False)
        nghttp = self.get_client("nghttp")
        curl = self.get_client("get_authenticated")
        cmd_args = nghttp.options[0]

        # Login with cURL to get authentication cookies
        self.login()
        cookie = self.get_client("login").cookie_string
        self.assertTrue(cookie)

        for uri in [
            "/wp-admin/index.php",  # Dashboard
            "/wp-admin/profile.php",
            "/wp-admin/edit-comments.php",
            "/wp-admin/edit.php",
        ]:
            with self.subTest("GET", uri=uri):
                curl.set_uri(uri)
                response = self.get_response(curl)
                self.assertEqual(response.status, 200, response)
                # Construct command with the Cookie header
                nghttp.options = [f"{cmd_args}'{uri}' --header 'Cookie: {cookie}'"]
                nghttp.start()
                self.wait_while_busy(nghttp)
                nghttp.stop()
                self.assertNotIn("Some requests were not processed", nghttp.response_msg)
                self.assertFalse(nghttp.response_msg)
