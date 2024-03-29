import json
import time

from framework import tester
from framework.curl_client import CurlClient, CurlResponse
from helpers import tf_cfg

# Number of open connections
CONCURRENT_CONNECTIONS = int(tf_cfg.cfg.get("General", "concurrent_connections"))
# Number of requests to make
REQUESTS_COUNT = int(tf_cfg.cfg.get("General", "stress_requests_count"))


class TestTempestaTechSite(tester.TempestaTest):
    proto = "https"

    backends = [
        {
            "id": "tempesta_tech_site",
            "type": "lxc",
            "container_name": "tempesta-site-stage",
            "ports": {8003: 80},
            "server_ip": "192.168.122.53",
            "healthcheck_command": "curl --fail localhost",
            # "container_create_command": [
            #     "/home/user/tempesta-tech.com/container/lxc/create.py",
            #     "--type=stage",
            # ],
            # "container_delete_command": [
            #     "/home/user/tempesta-tech.com/container/lxc/delete.sh",
            #     "tempesta-site-stage",
            # ],
            "make_snapshot": False,
        },
    ]

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

    tempesta_tmpl = """
            listen 443 proto=%s;

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
                    server ${server_ip}:8001;

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

    def setUp(self):
        if self._base:
            self.skipTest("This is an abstract class")
        self.tempesta = {
            "config": self.tempesta_tmpl % (self.proto),
        }
        curl_clients = [client for client in self.clients if not client.get("type")]
        for client in curl_clients:
            client.update(
                {
                    "type": "curl",
                    "ssl": True,
                }
            )
        super().setUp()
        self.get_client("get").clear_cookies()
        self.start_all_servers()

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.assertTrue(self.wait_all_connections(10))

    def get_response(self, client: CurlClient) -> CurlResponse:
        client.headers["Host"] = "tempesta-tech.com"
        self.restart_client(client)
        self.wait_while_busy(client)
        client.stop()
        return client.last_response

    def restart_client(self, client: CurlClient):
        if client.is_running():
            client.stop()
        client.start()
        if not client.is_running():
            raise Exception("Can not start client")

    def check_cached_headers(self, headers):
        """Return True if headers are from cached response."""
        return "age" in headers

    def login(self, user="ak@tempesta-tech.com", load_cookies=False):
        client: CurlClient = self.get_client("login")
        client.clear_cookies()
        client.data = f"log={user}&pwd=testpass"
        client.load_cookies = load_cookies

        response = self.get_response(client)
        self.assertEqual(response.status, 302)
        # Login page set multiple cookies
        self.assertGreater(len(response.multi_headers["set-cookie"]), 1)
        self.assertIn("/wp-admin/", response.headers["location"])
        self.assertFalse(self.check_cached_headers(response.headers))
        return response

    def post_form(self, uri, data, anonymous=True):
        client = self.get_client("post_form" if anonymous else "post_admin_form")
        client.load_cookies = not anonymous
        client.set_uri(uri)
        client.data = data
        response = self.get_response(client)
        self.assertFalse(self.check_cached_headers(response.headers))
        return response

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
        self.assertFalse(self.check_cached_headers(response.headers))
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
        self.assertFalse(self.check_cached_headers(response.headers))
        return response

    def approve_comment(self, comment_id):
        data = f"id={comment_id}&action=dim-comment&dimClass=unapproved&new=approved"
        response = self.post_form(uri="/wp-admin/admin-ajax.php", data=data, anonymous=False)
        self.assertEqual(response.status, 200, response)
        self.assertFalse(self.check_cached_headers(response.headers))

    def delete_comment(self, comment_id, action_nonce):
        data = f"id={comment_id}" f"&_ajax_nonce={action_nonce}" "&action=delete-comment" "&trash=1"
        response = self.post_form(uri="/wp-admin/admin-ajax.php", data=data, anonymous=False)
        self.assertEqual(response.status, 200, response)
        self.assertFalse(self.check_cached_headers(response.headers))

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
        self.assertFalse(self.check_cached_headers(response.headers))
        return nonce

    def get_comment_deletion_nonce(self, comment_id):
        client = self.get_client("get_authenticated")
        client.set_uri(f"/wp-admin/comment.php?action=editcomment&c={comment_id}")
        response = self.get_response(client)
        self.assertEqual(response.status, 200)
        nonce = re.search(r"action=trashcomment[^']+_wpnonce=([^']+)", response.stdout).group(1)
        self.assertTrue(nonce)
        self.assertFalse(self.check_cached_headers(response.headers))
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
        # self.start_all()
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
            # ("/?page_id=2", 200),  # page
            # ("/generated.php", 200),
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
        # self.start_all()
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
        # self.start_all()
        for i, load_cookies in enumerate((False, True, True), 1):
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
        # self.start_all()

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

        # Purge cache
        self.purge_cache(f"/?p={post_id}", fetch=True)
        self.purge_cache(f"/?feed=comments-rss2", fetch=True)

        # Check anonymous commend present
        self.assertIn(guest_comment, self.get_post(post_id).stdout)
        self.assertIn(guest_comment, self.get_comments_feed())

        # Delete comment
        self.delete_comment(
            comment_id=comment_id,
            action_nonce=self.get_comment_deletion_nonce(comment_id),
        )

        # Check deleted comment still present (cache not purged yet)
        self.assertIn(guest_comment, self.get_post(post_title).stdout)
        self.assertIn(guest_comment, self.get_comments_feed())

        # Purge cache
        self.purge_cache(f"/?p={post_id}", fetch=True)
        self.purge_cache(f"/?feed=comments-rss2", fetch=True)

        # Check comment removed from the page
        self.assertNotIn(guest_comment, self.get_post(post_title).stdout)
        self.assertNotIn(guest_comment, self.get_comments_feed())
