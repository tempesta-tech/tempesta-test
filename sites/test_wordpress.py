import json
import re
import time

from framework import tester
from framework.curl_client import CurlResponse
from helpers import tf_cfg

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'



class BaseWordpressTest(tester.TempestaTest, base=True):
    """Base class for WordPress tests."""

    proto = 'https'

    tempesta_tmpl = """
        listen 443 proto=%s;
        server ${server_ip}:${server_wordpress_port};

        tls_certificate ${general_workdir}/tempesta.crt;
        tls_certificate_key ${general_workdir}/tempesta.key;
        tls_match_any_server_name;

        # TODO: enable cache
        #cache 1;
        #cache_fulfill * *;
    """

    # Base Curl clients options
    clients = [
        {
            'id': 'get',
        },
        {
            'id': 'get_authenticated',
            'load_cookies': True,
        },
        {
            'id': 'get_silent',
            'disable_output': True,
        },
        {
            'id': 'login',
            'disable_output': True,
            'save_cookies': True,
            'uri': '/wp-login.php',
            'cmd_args': (
                ' --data "log=admin&pwd=secret"'
            ),
        },
        {
            'id': 'get_nonce',
            'load_cookies': True,
            'uri': '/wp-admin/admin-ajax.php?action=rest-nonce',
        },
        {
            'id': 'get_admin',
            'load_cookies': True,
            'uri': '/wp-admin/',
        },
        {
            'id': 'blog_post',
            'disable_output': True,
            'load_cookies': True,
            'uri': '/index.php?rest_route=/wp/v2/posts',
        },
        {
            'id': 'post_form',
            'cmd_args': (
                ' --header "Content-Type: application/x-www-form-urlencoded"'
            )
        },
        {
            'id': 'post_admin_form',
            'cmd_args': (
                ' --header "Content-Type: application/x-www-form-urlencoded"'
            )
        }
    ]

    def setUp(self):
        self.tempesta = {
            'config': self.tempesta_tmpl % (self.proto),
        }
        for client in self.clients:
            client.update({
                'type': 'curl',
                'ssl': True,
                'cmd_args': client.get('cmd_args', '') + ' --insecure',
                # TODO: remove, Tempesta address should be used
                'addr': '${server_ip}:${server_wordpress_port}',
            })
        super().setUp()

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
        return 'age' in headers

    def login(self, user='admin', load_cookies=False):
        client = self.get_client('login')
        client.load_cookies = load_cookies

        response = self.get_response(client)
        self.assertEqual(302, response.status)
        # Login page set multiple cookies
        self.assertGreater(len(response.multi_headers['set-cookie']), 1)
        self.assertTrue(response.headers['location'].endswith('/wp-admin/'))
        return response

    def post_form(self, uri, data, anonymous=True):
        client = self.get_client('post_form' if anonymous else 'post_admin_form')
        client.load_cookies = not anonymous
        client.set_uri(uri)
        client.data = data
        return self.get_response(client)

    def post_blog_post(self, title, nonce):
        client = self.get_client('blog_post')
        client.data = json.dumps({
            "title": title,
            "status": "draft",
            "content": "...",
            "excerpt": "",
            "status":"publish"
        })
        client.headers = {
            'Content-Type': 'application/json',
            'X-WP-Nonce': nonce,
        }
        response = self.get_response(client)
        self.assertEqual(201, response.status)
        try:
            post_id = re.search(
                r'=/wp/v2/posts/(\d+)',
                response.headers['location']
            ).group(1)
        except (IndexError, AttributeError):
            raise Exception(f"Can't find blog ID, headers: {response.headers}")
        tf_cfg.dbg(3, f"New post ID: {post_id}")
        return post_id

    def post_comment(self, post_id, text='Test', anonymous=True):
        data = (
            f"comment_post_ID={post_id}"
            f'&comment={text}'
            '&author=anonymous'
            '&email=guest%40example.com'
            '&submit=Post+Comment'
            '&comment_parent=0'
        )
        response = self.post_form(
            uri='/wp-comments-post.php',
            data=data,
            anonymous=anonymous
        )
        self.assertEqual(302, response.status, response)
        return response

    def approve_comment(self, comment_id):
        data = (
            f'id={comment_id}&action=dim-comment&dimClass=unapproved&new=approved'
        )
        response = self.post_form(
            uri='/wp-admin/admin-ajax.php',
            data=data,
            anonymous=False
        )
        self.assertEqual(200, response.status, response)

    def delete_comment(self, comment_id, action_nonce):
        data = (
            f"id={comment_id}"
            f"&_ajax_nonce={action_nonce}"
            '&action=delete-comment'
            '&trash=1'
        )
        response = self.post_form(
            uri='/wp-admin/admin-ajax.php',
            data=data,
            anonymous=False
        )
        self.assertEqual(200, response.status, response)

    def get_page_content(self, uri):
        client = self.get_client('get')
        client.set_uri(uri)
        response = self.get_response(client)
        self.assertEqual(200, response.status)
        self.assertFalse(response.stderr)
        return response.stdout

    def get_index(self):
        return self.get_page_content('/')

    def get_comments_feed(self):
        return self.get_page_content('/?feed=comments-rss2')

    def get_post(self, post_id):
        client = self.get_client("get")
        client.set_uri(f"/?p={post_id}")
        response = self.get_response(client)
        self.assertEqual(200, response.status)
        return response

    def get_nonce(self):
        client = self.get_client('get_nonce')
        response = self.get_response(client)
        self.assertEqual(200, response.status)
        nonce = response.stdout
        self.assertTrue(nonce)
        return nonce

    def get_comment_deletion_nonce(self, comment_id):
        client = self.get_client("get_authenticated")
        client.set_uri(f"/wp-admin/comment.php?action=editcomment&c={comment_id}")
        response = self.get_response(client)
        self.assertEqual(200, response.status)
        nonce = re.search(r"action=trashcomment[^']+_wpnonce=([^']+)", response.stdout).group(1)
        self.assertTrue(nonce)
        return nonce

    def test_get_resource(self):
        self.start_tempesta()
        client = self.get_client('get_silent')

        for uri, expected_code in [
                ('/empty.txt', 200),
                ('/hello.txt', 200),
                ('/?p=1', 200),
                ('/no-such-page-964f5300', 404)
        ]:
            with self.subTest('GET', uri=uri):
                client.set_uri(uri)
                response = self.get_response(client)
                self.assertEqual(response.status, expected_code, response)

    def test_page_cached(self):
        self.start_tempesta()
        client = self.get_client('get_silent')
        # TODO: replace with the valid page ID
        client.set_uri('/?page_id=128')

        with self.subTest('First request, expect non-cached response'):
            response = self.get_response(client)
            self.assertEqual(200, response.status)
            self.assertFalse(
                self.check_cached_headers(response.headers),
                f"Response headers: {response.headers}"
            )

        with self.subTest('Second request, expect cached response'):
            response = self.get_response(client)
            self.assertEqual(200, response.status)
            self.assertTrue(
                self.check_cached_headers(response.headers),
                f"Response headers: {response.headers}"
            )

    def test_auth_not_cached(self):
        """Authorisation requests must not be cached."""
        for i, load_cookies in enumerate((False, True), 1):
            with self.subTest('Login attempt', i=i, load_cookies=load_cookies):
                response = self.login(load_cookies=load_cookies)
                self.assertEqual(
                    False,
                    self.check_cached_headers(response.headers),
                    f"Response headers: {response.headers}"
                )

    def test_blog_post_flow(self):
        post_title = f"@{time.time()}_post_title@"
        user_comment = f"@{time.time()}_user_comment@"
        guest_comment = f"@{time.time()}_guest_comment@"
        self.start_tempesta()

        # Check index page
        self.assertNotIn(post_title, self.get_index())

        # Login
        self.login()

        # Obtain nonce
        nonce = self.get_nonce()

        # Publish new blog post
        post_id = self.post_blog_post(title=post_title, nonce=nonce)

        # Post title presented on the blog
        self.assertIn(post_title, self.get_index())

        # Get new blog post content
        content = self.get_page_content(f"/?p={post_id}")
        self.assertIn(post_title, content)

        # No comments yet
        self.assertNotIn(guest_comment, content)
        self.assertNotIn(user_comment, content)
        feed = self.get_comments_feed()
        self.assertNotIn(user_comment, feed)
        self.assertNotIn(guest_comment, feed)

        # Post comment from user
        self.post_comment(post_id, anonymous=False, text=user_comment)
        response = self.get_post(post_id)
        # Check user commend present
        self.assertIn(user_comment, response.stdout)
        # Comment presented in the comments feed
        self.assertIn(user_comment, self.get_comments_feed())

        # Post comment from anonymous
        response = self.post_comment(post_id, anonymous=True, text=guest_comment)
        try:
            comment_id = re.search(
                r'#comment-(\d+)$',
                response.headers['location']
            ).group(1)
        except (AttributeError, KeyError):
            raise Exception(f"Can't find comment ID, headers: {response.headers}")

        # Approve comment
        client = self.get_client('post_admin_form')
        self.approve_comment(comment_id)

        # Check anonymous commend present
        self.assertIn(guest_comment, self.get_post(post_id).stdout)
        self.assertIn(guest_comment, self.get_comments_feed())

        # Delete comment
        self.delete_comment(
            comment_id=comment_id,
            action_nonce=self.get_comment_deletion_nonce(comment_id)
        )

        # Check comment removed from the page
        self.assertNotIn(guest_comment, self.get_post(post_id).stdout)
        self.assertNotIn(guest_comment, self.get_comments_feed())

    def test_blog_post_cached(self):
        post_title = f"@{time.time()}_post_title@"
        self.start_tempesta()
        self.login()
        post_id = self.post_blog_post(title=post_title, nonce=self.get_nonce())

        client = self.get_client("get")
        client.set_uri(f"/?p={post_id}")
        for i, cached in enumerate([False, False, False], 1):  # TODO: should be cached
            with self.subTest('Get blog post', i=i, expect_cached=cached):
                content = self.get_page_content(f"/?p={post_id}")
                response = self.get_response(client)
                self.assertEqual(200, response.status)
                self.assertIn(post_title, response.stdout)
                self.assertEqual(
                    cached,
                    self.check_cached_headers(response.headers),
                    f"Response headers: {response.headers}"
                )


class TestWordpressSite(BaseWordpressTest):

    proto = 'https'


class TestWordpressSiteH2(BaseWordpressTest):

    proto = 'h2'

    def setUp(self):
        for client in self.clients:
            client.update({
                'http2': True,
            })
        super().setUp()
