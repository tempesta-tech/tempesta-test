import json
import re
import time

from framework import tester
from framework.mixins import NetfilterMarkMixin
from framework.curl_client import CurlResponse
from helpers import tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"


class BaseWordpressTest(NetfilterMarkMixin, tester.TempestaTest, base=True):
    """Base class for WordPress tests."""

    proto = "https"

    backends = [
        {
            "id": "wordpress",
            "type": "docker",
            "image": "wordpress",
            "ports": {8000: 80},
            "env": {
                "WP_HOME": "https://${tempesta_ip}/",
                "WP_SITEURL": "https://${tempesta_ip}/",
            },
        },
    ]

    tempesta_tmpl = """
        listen 443 proto=%s;
        srv_group wordpress {
            server ${server_ip}:8000;
        }

        tls_certificate ${general_workdir}/tempesta.crt;
        tls_certificate_key ${general_workdir}/tempesta.key;
        tls_match_any_server_name;

        vhost tempesta-tech.com {
            proxy_pass wordpress;
        }

       http_chain admin_rules {
            mark == 1 -> $$cache = 0;
            -> tempesta-tech.com;
       }

       http_chain {
            # Access to admin section is restricted by Netfilter mark
            mark == 1 -> admin_rules;
            uri == "/wp-admin*" -> block;

            cookie "wordpress_logged_in_*" == "*" -> $$cache = 0;
            cookie "wp-postpass_*" == "*" -> $$cache = 0;
            cookie "comment_author_*" == "*" -> $$cache = 0;

            -> tempesta-tech.com;
        }

        cache 1;
        cache_fulfill * *;
        cache_methods GET;
        cache_bypass prefix "/wp-admin/";
        cache_purge;
        cache_purge_acl ${client_ip};
    """

    # Base Curl clients options
    clients = [
        {
            "id": "get",
        },
        {
            "id": "get_authenticated",
            "load_cookies": True,
        },
        {
            "id": "login",
            "save_cookies": True,
            "uri": "/wp-login.php",
            "data": "log=admin&pwd=secret",
        },
        {
            "id": "get_nonce",
            "load_cookies": True,
            "uri": "/wp-admin/admin-ajax.php?action=rest-nonce",
        },
        {
            "id": "get_admin",
            "load_cookies": True,
            "uri": "/wp-admin/",
        },
        {
            "id": "blog_post",
            "load_cookies": True,
            "uri": "/index.php?rest_route=/wp/v2/posts",
        },
        {
            "id": "post_form",
            "headers": {
                "Content-Type": "application/x-www-form-urlencoded",
            },
        },
        {
            "id": "post_admin_form",
            "headers": {
                "Content-Type": "application/x-www-form-urlencoded",
            },
        },
        {
            "id": "purge_cache",
            # Set max-time to prevent hang caused by Tempesta FW #1692
            "cmd_args": "--request PURGE --max-time 1",
        },
    ]

    def setUp(self):
        if self._base:
            self.skipTest("This is an abstract class")
        self.tempesta = {
            "config": self.tempesta_tmpl % (self.proto),
        }
        for client in self.clients:
            client.update(
                {
                    "type": "curl",
                    "ssl": True,
                }
            )
        super().setUp()

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.assertTrue(self.wait_all_connections(5))

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
            raise Exception("Can not start client")

    def check_cached_headers(self, headers):
        """Return True if headers are from cached response."""
        self.assertIn("x-powered-by", headers.keys(), "Unexpected headers (not from WordPress?)")
        return "age" in headers

    def login(self, user="admin", load_cookies=False):
        client = self.get_client("login")
        client.load_cookies = load_cookies

        response = self.get_response(client)
        self.assertEqual(response.status, 302)
        # Login page set multiple cookies
        self.assertGreater(len(response.multi_headers["set-cookie"]), 1)
        self.assertTrue(response.headers["location"].endswith("/wp-admin/"))
        return response

    def post_form(self, uri, data, anonymous=True):
        client = self.get_client("post_form" if anonymous else "post_admin_form")
        client.load_cookies = not anonymous
        client.set_uri(uri)
        client.data = data
        return self.get_response(client)

    def post_blog_post(self, title, nonce):
        client = self.get_client("blog_post")
        client.data = json.dumps(
            {
                "title": title,
                "status": "draft",
                "content": "...",
                "excerpt": "",
                "status": "publish",
            }
        )
        client.headers = {
            "Content-Type": "application/json",
            "X-WP-Nonce": nonce,
        }
        response = self.get_response(client)
        self.assertEqual(response.status, 201)
        try:
            post_id = re.search(r"=/wp/v2/posts/(\d+)", response.headers["location"]).group(1)
        except (IndexError, AttributeError):
            raise Exception(f"Can't find blog ID, headers: {response.headers}")
        tf_cfg.dbg(3, f"New post ID: {post_id}")
        return post_id

    def post_comment(self, post_id, text="Test", anonymous=True):
        data = (
            f"comment_post_ID={post_id}"
            f"&comment={text}"
            "&author=anonymous"
            "&email=guest%40example.com"
            "&submit=Post+Comment"
            "&comment_parent=0"
        )
        response = self.post_form(uri="/wp-comments-post.php", data=data, anonymous=anonymous)
        self.assertEqual(response.status, 302, response)
        return response

    def approve_comment(self, comment_id):
        data = f"id={comment_id}&action=dim-comment&dimClass=unapproved&new=approved"
        response = self.post_form(uri="/wp-admin/admin-ajax.php", data=data, anonymous=False)
        self.assertEqual(response.status, 200, response)

    def delete_comment(self, comment_id, action_nonce):
        data = f"id={comment_id}" f"&_ajax_nonce={action_nonce}" "&action=delete-comment" "&trash=1"
        response = self.post_form(uri="/wp-admin/admin-ajax.php", data=data, anonymous=False)
        self.assertEqual(response.status, 200, response)

    def get_page_content(self, uri):
        client = self.get_client("get")
        client.set_uri(uri)
        response = self.get_response(client)
        self.assertEqual(response.status, 200)
        self.assertFalse(response.stderr)
        return response.stdout

    def get_index(self):
        return self.get_page_content("/")

    def get_comments_feed(self):
        return self.get_page_content("/?feed=comments-rss2")

    def get_post(self, post_id):
        client = self.get_client("get")
        client.set_uri(f"/?p={post_id}")
        response = self.get_response(client)
        self.assertEqual(response.status, 200)
        return response

    def get_nonce(self):
        client = self.get_client("get_nonce")
        response = self.get_response(client)
        self.assertEqual(response.status, 200)
        nonce = response.stdout
        self.assertTrue(nonce)
        return nonce

    def get_comment_deletion_nonce(self, comment_id):
        client = self.get_client("get_authenticated")
        client.set_uri(f"/wp-admin/comment.php?action=editcomment&c={comment_id}")
        response = self.get_response(client)
        self.assertEqual(response.status, 200)
        nonce = re.search(r"action=trashcomment[^']+_wpnonce=([^']+)", response.stdout).group(1)
        self.assertTrue(nonce)
        return nonce

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
        self.start_all()
        client = self.get_client("get")
        for uri, expected_code in [
            ("/empty.txt", 200),
            ("/hello.txt", 200),
            ("/images/128.jpg", 200),  # small image
            ("/images/2048.jpg", 200),  # large image
            ("/", 200),  # index
            ("/?p=1", 200),  # blog post
            ("/?page_id=2", 200),  # page
            ("/generated.php", 200),
            ("/?page_id=99999999999", 404),
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
        uri = "/?page_id=2"  # About page
        self.start_all()
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
        for i, load_cookies in enumerate((False, True), 1):
            with self.subTest("Login attempt", i=i, load_cookies=load_cookies):
                response = self.login(load_cookies=load_cookies)
                self.assertEqual(
                    self.check_cached_headers(response.headers),
                    False,
                    f"Response headers: {response.headers}",
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
            comment_id = re.search(r"#comment-(\d+)$", response.headers["location"]).group(1)
        except (AttributeError, KeyError):
            raise Exception(f"Can't find comment ID, headers: {response.headers}")

        # Approve comment
        client = self.get_client("post_admin_form")
        self.approve_comment(comment_id)

        # Check anonymous commend present
        self.assertIn(guest_comment, self.get_post(post_id).stdout)
        self.assertIn(guest_comment, self.get_comments_feed())

        # Delete comment
        self.delete_comment(
            comment_id=comment_id,
            action_nonce=self.get_comment_deletion_nonce(comment_id),
        )

        # Purge cache
        self.purge_cache(f"/?p={post_id}", fetch=True)
        self.purge_cache(f"/?feed=comments-rss2", fetch=True)

        # Check comment removed from the page
        self.assertNotIn(guest_comment, self.get_post(post_id).stdout)
        self.assertNotIn(guest_comment, self.get_comments_feed())

    def test_blog_post_cached(self):
        post_id = "1"  # Use 'Hello world!' post
        self.start_all()

        client = self.get_client("get")
        client.set_uri(f"/?p={post_id}")
        for i, cached in enumerate([False, True, True], 1):
            with self.subTest("Get blog post", i=i, expect_cached=cached):
                response = self.get_response(client)
                self.assertEqual(response.status, 200)
                self.assertFalse(response.stderr)
                self.assertTrue(response.stdout.endswith("</html>\n"))
                self.assertGreater(len(response.stdout), 65000, len(response.stdout))
                length = response.headers.get("content-length")
                if length:
                    self.assertEqual(len(response.stdout_raw), int(length))
                elif cached:
                    raise Exception("No Content-Length for cached response", response.headers)
                self.assertIn(
                    (
                        "Welcome to WordPress. "
                        "This is your first post. "
                        "Edit or delete it, then start writing!"
                    ),
                    response.stdout,
                )
                self.assertEqual(
                    self.check_cached_headers(response.headers),
                    cached,
                    f"Response headers: {response.headers}",
                )

    def test_admin_resource_restricted_by_http_rule(self):
        self.start_all()
        client = self.get_client("get")
        client.set_uri("/wp-admin/")

        with self.subTest("Access is blocked if mark not set"):
            response = self.get_response(client)
            self.assertFalse(response)

        with self.subTest("Access is allowed if mark set"):
            self.set_nf_mark(1)
            response = self.get_response(client)
            self.assertEqual(response.status, 302)
            self.assertIn("wp-login.php", response.headers["location"])


class TestWordpressSite(BaseWordpressTest):

    proto = "https"


class TestWordpressSiteH2(BaseWordpressTest):

    proto = "h2"

    def setUp(self):
        for client in self.clients:
            client.update(
                {
                    "http2": True,
                }
            )
        self.clients.append({
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
        })
        super().setUp()

    def test_get_resource_with_assets(self):
        self.start_all()
        client = self.get_client("nghttp")
        cmd_args = client.options[0]

        for uri in [
            "/hello.txt",  # small file
            "/", # index
            "/?page_id=2",  # page with short text
            "/?page_id=3",  # page with long text
            "/?p=1",  # blog post
            "/?p=100", # blog post with image and comments
            "/images.html",  # page with one big and 3 small images
            "/images.php?n=1&max=128",  # page with a single small image
            "/images.php?n=1&max=2048", # page with a big image
            "/images.php?n=16&max=128",
            "/images.php?n=16&max=2048",
        ]:
            with self.subTest("GET", uri=uri):
                client.options = [cmd_args + uri]
                client.start()
                self.wait_while_busy(client)
                client.stop()
                self.assertNotIn("Some requests were not processed", client.response_msg)
                self.assertFalse(client.response_msg)
