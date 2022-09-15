import re

from framework import tester
from framework.curl_client import CurlResponse

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class TestGetWordpressPages(tester.TempestaTest):

    tempesta = {
        'config':
        """
        listen 80;
        cache 1;
        cache_fulfill * *;
        server ${server_ip}:${server_wordpress_port};
        """
    }

    clients = [
        {
            'id': 'get_page',
            'type': 'curl',
            'ssl': False,
            'disable_output': True,
            'uri': '/?page_id=1370',  # TODO: replace with the valid page ID
        },
        {
            'id': 'login',
            'type': 'curl',
            'ssl': False,
            'disable_output': True,
            'save_cookies': True,
            'addr': '${server_ip}:${server_wordpress_port}',  # TODO
            'uri': '/wp-login.php',
            'cmd_args': (
                '--data "log=admin&pwd=secret"'
            ),
        },
        {
            'id': 'get_nonce',
            'type': 'curl',
            'ssl': False,
            'disable_output': False,
            'load_cookies': True,
            'addr': '${server_ip}:${server_wordpress_port}',  # TODO
            'uri': '/wp-admin/admin-ajax.php?action=rest-nonce',
        },
        {
            'id': 'blog_post',
            'type': 'curl',
            'ssl': False,
            'disable_output': True,
            'load_cookies': True,
            'addr': '${server_ip}:${server_wordpress_port}',  # TODO
            'uri': '/index.php?rest_route=/wp/v2/posts',
            'cmd_args': (
                '-H "Content-Type: application/json"'
                " --data '"
                '{"status":"draft","title":"@test-new-post@","content":"...",'
                '"excerpt":"","status":"publish"}'
                "'"
            ),
        },
        {
            'id': 'get_new_blog_post',
            'type': 'curl',
            'ssl': False,
            'addr': '${server_ip}:${server_wordpress_port}',  # TODO
            # URI is filled with a created post ID
            'uri': '!--set-by-test--!',
            'disable_output': False,
        },
    ]

    def get_response(self, client) -> CurlResponse:
        self.restart_client(client)
        self.wait_while_busy(client)
        client.stop()
        return client.last_response

    def restart_client(self, client):
        if client.is_running():
            client.stop()
        client.start()
        if not client.is_running():
            raise Exception('Can not start client')

    def check_cached_headers(self, headers):
        """Return True if headers are from cached response."""
        self.assertIn(
            'x-powered-by',
            headers.keys(),
            "Unexpected headers (not from WordPress?)"
        )
        return 'age' in headers.keys()

    def login(self, load_cookies=False):
        client = self.get_client("login")
        self.assertFalse(client.load_cookies)
        if load_cookies:
            client.load_cookies = True

        response = self.get_response(client)
        self.assertEqual(302, response.status_code)
        self.assertGreater(len(response.headers['set-cookie']), 1)
        self.assertTrue(response.headers['location'][0].endswith('/wp-admin/'))
        return response

    def test_page_cached(self):
        self.start_tempesta()
        client = self.get_client("get_page")

        with self.subTest("First request, expect non-cached response"):
            response = self.get_response(client)
            self.assertEqual(200, response.status_code)
            self.assertFalse(
                self.check_cached_headers(response.headers),
                f"Response headers: {response.headers}"
            )

        with self.subTest("Second request, expect cached response"):
            response = self.get_response(client)
            self.assertEqual(200, response.status_code)
            self.assertTrue(
                self.check_cached_headers(response.headers),
                f"Response headers: {response.headers}"
            )

    def test_auth_not_cached(self):
        """Authorisation requests must not be cached."""
        for i, load_cookies in enumerate((False, True), 1):
            with self.subTest("Login attempt", i=i, load_cookies=load_cookies):
                response = self.login(load_cookies=load_cookies)
                self.assertEqual(
                    False,
                    self.check_cached_headers(response.headers),
                    f"Response headers: {response.headers}"
                )

    def test_blog_post_created(self):
        self.start_tempesta()

        with self.subTest("Login"):
            self.login()

        with self.subTest("Obtain nonce"):
            client = self.get_client("get_nonce")
            response = self.get_response(client)
            self.assertEqual(200, response.status_code)
            nonce = response.stdout
            self.assertTrue(nonce)

        with self.subTest("Publish new blog post"):
            client = self.get_client("blog_post")
            client.options.append(f"-H 'X-WP-Nonce: {nonce}'")
            response = self.get_response(client)
            self.assertEqual(201, response.status_code)
            try:
                post_id = re.search(
                    r'=/wp/v2/posts/(\d+)',
                    response.headers['location'][0]
                ).group(1)
            except (IndexError, AttributeError):
                raise Exception(f"Can't find blog ID, headers: {response.headers}")

        client = self.get_client("get_new_blog_post")
        client.set_uri(f"/?p={post_id}")
        for i, cached in enumerate([False, False, False], 1):  # TODO: should be cached
            with self.subTest("Get blog post", i=i, expect_cached=cached):
                response = self.get_response(client)
                self.assertEqual(200, response.status_code)
                self.assertIn('<title>@test-new-post@', response.stdout)
                self.assertEqual(
                    cached,
                    self.check_cached_headers(response.headers),
                    f"Response headers: {response.headers}"
                )
