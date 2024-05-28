"""Functional tests of caching different methods."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework.deproxy_client import DeproxyClient
from framework.deproxy_server import StaticDeproxyServer
from framework.parameterize import param, parameterize
from framework.tester import TempestaTest
from helpers import checks_for_tests as checks
from helpers import dmesg, tf_cfg
from helpers.deproxy import HttpMessage


class TestPurgeAcl(TempestaTest):
    tempesta = {
        "config": """
listen ${tempesta_ip}:80;
listen [${tempesta_ipv6}]:80;

server ${server_ip}:8000;

cache 2;
cache_fulfill * *;
cache_methods GET;
cache_purge;
"""
    }

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + "Content-Length: 0\r\n"
                + "Server: Deproxy Server\r\n"
                + "\r\n"
            ),
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

    @parameterize.expand(
        [
            param(name="ipv4", purge_ip=tf_cfg.cfg.get("Client", "ip"), family="ipv4"),
            param(name="ipv6", purge_ip=tf_cfg.cfg.get("Client", "ipv6"), family="ipv6"),
            param(
                name="ipv4_with_mask", purge_ip=f'{tf_cfg.cfg.get("Client", "ip")}/8', family="ipv4"
            ),
            param(
                name="ipv6_with_mask",
                purge_ip=f'{tf_cfg.cfg.get("Client", "ipv6")}/120',
                family="ipv6",
            ),
            param(
                name="ipv4_and_ipv6",
                purge_ip=f'{tf_cfg.cfg.get("Client", "ip")} {tf_cfg.cfg.get("Client", "ipv6")}',
                family="ipv4",
            ),
        ]
    )
    def test_purge_acl(self, name, purge_ip, family):
        tempesta = self.get_tempesta()
        client = self.get_client("deproxy")
        srv = self.get_server("deproxy")

        tempesta.config.set_defconfig(tempesta.config.defconfig + f"cache_purge_acl {purge_ip};\n")
        client.bind_addr = tf_cfg.cfg.get("Client", "ip" if family == "ipv4" else "ipv6")
        client.socket_family = family
        client.conn_addr = tf_cfg.cfg.get("Tempesta", "ip" if family == "ipv4" else "ipv6")
        request = client.create_request(method="GET", uri="/page.html", headers=[])

        self.start_all_services()

        client.send_request(request, "200")
        client.send_request(request, "200")
        self.assertIn("age", client.last_response.headers)
        self.assertEqual(len(srv.requests), 1)

        client.send_request(
            client.create_request(method="PURGE", uri="/page.html", headers=[]),
            "200",
        )

        # cached responses was removed
        client.send_request(request, "200")
        self.assertNotIn("age", client.last_response.headers)
        self.assertEqual(len(srv.requests), 2)

    def test_purge_fail(self):
        """
        Send a request and cache it. Use PURGE and repeat the request. Check that a response is
        not received from cache, but the request has been cached again.
        """
        self.start_all_services()
        client = self.get_client("deproxy")

        # All cacheable method to the resource must be cached
        client.send_request(client.create_request(method="PURGE", uri="/page.html", headers=[]), "403")
        self.assertFalse(client.conn_is_closed)

    def test_purge_acl_fail(self):
        tempesta = self.get_tempesta()
        client = self.get_client("deproxy")

        tempesta.config.set_defconfig(tempesta.config.defconfig + f"cache_purge_acl 2.2.2.2;\n")
        self.start_all_services()

        client.send_request(client.create_request(method="PURGE", uri="/page.html", headers=[]), "403")
        self.assertFalse(client.conn_is_closed)



class TestPurgeBase(TempestaTest):
    tempesta_template = {
        "config": """
listen 80;

server ${server_ip}:8000;

vhost default {
    proxy_pass default;
}

cache %(cache_val)s;
cache_fulfill * *;
cache_methods GET HEAD;
cache_purge;
cache_purge_acl ${client_ip};
cache_resp_hdr_del set-cookie;

frang_limits {
  http_methods GET PURGE;
}
""",
    }

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + "Connection: keep-alive\r\n"
                + "Content-Length: 13\r\n"
                + "Content-Type: text/html\r\n"
                + "Server: Deproxy Server\r\n"
                + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
                + f"Date: {HttpMessage.date_time_string()}\r\n"
                + "\r\n"
                + "<html></html>"
            ),
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

    request_template = (
        "{0} /page.html HTTP/1.1\r\n"
        + "Host: {0}\r\n".format(tf_cfg.cfg.get("Client", "hostname"))
        + "Connection: keep-alive\r\n"
        + "Accept: */*\r\n"
        + "\r\n"
    )

    def set_cache_val(self, cache_val):
        self.tempesta["config"] = self.tempesta_template["config"] % {
            "cache_val": cache_val,
        }
        TempestaTest.setUp(self)
        self.start_all_services()


class TestPurgeNoCache(TestPurgeBase):
    def setUp(self):
        self.set_cache_val(0)

    def test_purge(self):
        client: DeproxyClient = self.get_client("deproxy")
        srv: StaticDeproxyServer = self.get_server("deproxy")

        client.send_request(self.request_template.format("PURGE"), "403")
        self.assertEqual(len(srv.requests), 0)


class TestPurge(TestPurgeBase):
    """This class contains checks for PURGE method operation."""

    request_template_x_tempesta_cache = (
        "{0} /page.html HTTP/1.1\r\n"
        + "Host: {0}\r\n".format(tf_cfg.cfg.get("Client", "hostname"))
        + "Connection: keep-alive\r\n"
        + "Accept: */*\r\n"
        + "x-tempesta-cache: {1}\r\n"
        + "\r\n"
    )

    def setUp(self):
        self.set_cache_val(2)

    def test_purge(self):
        """
        Send a request and cache it. Use PURGE and repeat the request. Check that a response is
        not received from cache, but the request has been cached again.
        """
        self.start_all_services()
        client: DeproxyClient = self.get_client("deproxy")
        srv: StaticDeproxyServer = self.get_server("deproxy")

        # All cacheable method to the resource must be cached
        client.send_request(self.request_template.format("GET"), "200")
        self.assertNotIn("age", client.last_response.headers)

        client.send_request(self.request_template.format("GET"), "200")
        self.assertIn("age", client.last_response.headers)
        client.send_request(self.request_template.format("HEAD"), "200")
        self.assertIn("age", client.last_response.headers)

        self.assertEqual(len(srv.requests), 1)
        client.send_request(self.request_template.format("PURGE"), "200")
        self.assertEqual(len(srv.requests), 1)

        # All cached responses was removed, expect re-caching them
        client.send_request(self.request_template.format("GET"), "200")
        self.assertNotIn("age", client.last_response.headers)

        client.send_request(self.request_template.format("GET"), "200")
        self.assertIn("age", client.last_response.headers)
        client.send_request(self.request_template.format("HEAD"), "200")
        self.assertIn("age", client.last_response.headers)

        checks.check_tempesta_cache_stats(
            self.get_tempesta(), cache_hits=4, cache_misses=2, cl_msg_served_from_cache=4
        )
        self.assertEqual(len(self.get_server("deproxy").requests), 2)

    def test_purge_get_basic(self):
        """
        Send a request and cache it. Use PURGE with "x-tempesta-cache: GET" header and repeat the
        request. Check that tempesta has sent a request to update cache for "GET" method. But cache
        for "HEAD" method has been purged.
        """
        self.start_all_services()
        client: DeproxyClient = self.get_client("deproxy")
        srv: StaticDeproxyServer = self.get_server("deproxy")

        # All cacheable method to the resource must be cached
        client.send_request(self.request_template.format("GET"), "200")
        self.assertNotIn("age", client.last_response.headers)

        client.send_request(self.request_template.format("GET"), "200")
        self.assertIn("age", client.last_response.headers)
        client.send_request(self.request_template.format("HEAD"), "200")
        self.assertIn("age", client.last_response.headers)

        # PURGE + GET works like a cache update, so all following requests
        # must be served from the cache.
        self.assertEqual(len(srv.requests), 1)
        client.send_request(self.request_template_x_tempesta_cache.format("PURGE", "GET"), "200")
        self.assertEqual(len(srv.requests), 2)

        # Note that due to how Tempesta handles HEAD this doesn't help us
        # with HEAD pre-caching.
        client.send_request(self.request_template.format("GET"), "200")
        self.assertIn("age", client.last_response.headers)

        client.send_request(self.request_template.format("HEAD"), "200")
        self.assertIn("age", client.last_response.headers)

        checks.check_tempesta_cache_stats(
            self.get_tempesta(),
            cache_hits=4,
            cache_misses=1,
            cl_msg_served_from_cache=4,
        )
        self.assertEqual(len(srv.requests), 2)

    def test_purge_get_update(self):
        """
        Send a request and cache it. Update server response. Use PURGE with "x-tempesta-cache: GET"
        header and repeat the request. Check that cached response has been update.
        """
        self.start_all_services()
        client: DeproxyClient = self.get_client("deproxy")
        srv: StaticDeproxyServer = self.get_server("deproxy")

        client.send_request(self.request_template.format("GET"), "200")
        self.assertNotIn("age", client.last_response.headers)
        client.send_request(self.request_template.format("GET"), "200")
        self.assertIn("age", client.last_response.headers)

        new_response_body = "New text page"
        srv.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-Length: 13\r\n"
            + "Content-Type: text/html\r\n"
            + "Server: Deproxy Server\r\n"
            + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + "\r\n"
            + new_response_body,
        )
        self.assertEqual(len(srv.requests), 1)
        client.send_request(self.request_template_x_tempesta_cache.format("PURGE", "GET"), "200")
        self.assertEqual(len(srv.requests), 2)

        client.send_request(self.request_template.format("GET"), "200")
        self.assertIn("age", client.last_response.headers)
        self.assertEqual(new_response_body, client.last_response.body)

        checks.check_tempesta_cache_stats(
            self.get_tempesta(),
            cache_hits=2,
            cache_misses=1,
            cl_msg_served_from_cache=2,
        )
        self.assertEqual(len(srv.requests), 2)

    def test_purge_get_update_hdr_del(self):
        """
        Send a request and cache it. Update server response with "Set-Cookie" header. Use PURGE
        with "x-tempesta-cache: GET" header and repeat the request. Check that cached response has
        not "Set-Cookie" header.
        """
        self.start_all_services()
        self.disable_deproxy_auto_parser()
        client: DeproxyClient = self.get_client("deproxy")
        srv: StaticDeproxyServer = self.get_server("deproxy")

        client.send_request(self.request_template.format("GET"), "200")
        self.assertNotIn("age", client.last_response.headers)
        client.send_request(self.request_template.format("GET"), "200")
        self.assertIn("age", client.last_response.headers)

        new_response_body = "New text page"
        srv.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-Length: 13\r\n"
            + "Content-Type: text/html\r\n"
            + "Server: Deproxy Server\r\n"
            + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + "Set-Cookie: somecookie=2\r\n"
            + "\r\n"
            + new_response_body,
        )

        self.assertEqual(len(srv.requests), 1)
        client.send_request(self.request_template_x_tempesta_cache.format("PURGE", "GET"), "200")
        self.assertIn("set-cookie", client.last_response.headers)
        self.assertEqual(len(srv.requests), 2)

        client.send_request(self.request_template.format("GET"), "200")
        self.assertIn("age", client.last_response.headers)
        self.assertEqual(new_response_body, client.last_response.body)
        self.assertNotIn("set-cookie", client.last_response.headers)

        checks.check_tempesta_cache_stats(
            self.get_tempesta(),
            cache_hits=2,
            cache_misses=1,
            cl_msg_served_from_cache=2,
        )
        self.assertEqual(len(srv.requests), 2)

    def test_purge_get_update_cc(self):
        """
        And another PURGE-GET test, with Set-Cookie removed due to no-cache="set-cookie" in the
        response.
        """
        self.start_all_services()
        self.disable_deproxy_auto_parser()
        client: DeproxyClient = self.get_client("deproxy")
        srv: StaticDeproxyServer = self.get_server("deproxy")

        client.send_request(self.request_template.format("GET"), "200")
        self.assertNotIn("age", client.last_response.headers)

        client.send_request(self.request_template.format("GET"), "200")
        self.assertIn("age", client.last_response.headers)

        new_response_body = "New text page"
        srv.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-Length: 13\r\n"
            + "Content-Type: text/html\r\n"
            + "Server: Deproxy Server\r\n"
            + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + "Set-Cookie: somecookie=2\r\n"
            + 'Cache-Control: no-cache="set-cookie"\r\n'
            + "\r\n"
            + new_response_body,
        )

        self.assertEqual(len(srv.requests), 1)
        client.send_request(self.request_template_x_tempesta_cache.format("PURGE", "GET"), "200")
        self.assertEqual(len(srv.requests), 2)
        self.assertIn("set-cookie" and "cache-control", client.last_response.headers)

        client.send_request(self.request_template.format("GET"), "200")
        self.assertIn("age" and "cache-control", client.last_response.headers)
        self.assertNotIn("set-cookie:", client.last_response.headers)

        checks.check_tempesta_cache_stats(
            self.get_tempesta(),
            cache_hits=2,
            cache_misses=1,
            cl_msg_served_from_cache=2,
        )
        self.assertEqual(len(srv.requests), 2)

    def test_useless_x_tempesta_cache(self):
        """
        Send an ordinary GET request with an "X-Tempesta-Cache" header, and make sure it doesn't
        affect anything.
        """
        self.start_all_services()
        client: DeproxyClient = self.get_client("deproxy")

        client.send_request(self.request_template_x_tempesta_cache.format("GET", "GET"), "200")

        client.send_request(self.request_template_x_tempesta_cache.format("GET", "GET"), "200")
        self.assertIn("age", client.last_response.headers)

        checks.check_tempesta_cache_stats(
            self.get_tempesta(),
            cache_hits=1,
            cache_misses=1,
            cl_msg_served_from_cache=1,
        )
        self.assertEqual(len(self.get_server("deproxy").requests), 1)

    def test_purge_get_garbage(self):
        """
        Send some garbage in the "X-Tempesta-Cache" header. The entry must be purged, but not
        re-cached. (This works the same way as a plain PURGE, so we're not using the helper
        method here.)
        """
        self.start_all_services()
        client: DeproxyClient = self.get_client("deproxy")
        srv: StaticDeproxyServer = self.get_server("deproxy")

        client.send_request(self.request_template.format("GET"), "200")
        self.assertNotIn("age", client.last_response.headers)

        client.send_request(self.request_template.format("GET"), "200")
        self.assertIn("age", client.last_response.headers)

        self.assertEqual(len(srv.requests), 1)
        client.send_request(self.request_template_x_tempesta_cache.format("PURGE", "FRED"), "200")
        self.assertEqual(len(srv.requests), 1)

        client.send_request(self.request_template.format("GET", ""), "200")
        self.assertNotIn("age", client.last_response.headers)

        client.send_request(self.request_template.format("GET"), "200")
        self.assertIn("age", client.last_response.headers)

        self.assertEqual(len(srv.requests), 2)
        client.send_request(
            self.request_template_x_tempesta_cache.format("PURGE", "GETWRONG"),
            "200",
        )
        self.assertNotIn("age", client.last_response.headers)
        self.assertEqual(len(srv.requests), 2)

        client.send_request(self.request_template.format("GET"), "200")
        self.assertNotIn("age", client.last_response.headers)

        client.send_request(self.request_template.format("GET"), "200")
        self.assertIn("age", client.last_response.headers)

        checks.check_tempesta_cache_stats(
            self.get_tempesta(),
            cache_hits=3,
            cache_misses=3,
            cl_msg_served_from_cache=3,
        )
        self.assertEqual(len(srv.requests), 3)

    def test_purge_get_uncached(self):
        """
        Send a PURGE request with X-Tempesta-Cache for a non-cached entry. Make sure a new cache
        entry is populated after the request.
        """
        self.start_all_services()
        client: DeproxyClient = self.get_client("deproxy")
        srv: StaticDeproxyServer = self.get_server("deproxy")

        client.send_request(self.request_template_x_tempesta_cache.format("PURGE", "GET"), "200")

        client.send_request(self.request_template.format("GET"), "200")
        self.assertIn("age", client.last_response.headers)

        checks.check_tempesta_cache_stats(
            self.get_tempesta(),
            cache_hits=1,
            cache_misses=0,
            cl_msg_served_from_cache=1,
        )
        self.assertEqual(len(srv.requests), 1)

    def test_purge_get_uncacheable(self):
        """
        Send a PURGE request with "X-Tempesta-Cache" for an existing cache entry, and generate a
        non-cacheable response. Make sure that there is neither the old nor the new response in
        the cache.
        """
        self.start_all_services()
        client: DeproxyClient = self.get_client("deproxy")
        srv: StaticDeproxyServer = self.get_server("deproxy")

        client.send_request(self.request_template.format("GET"), "200")
        self.assertNotIn("age", client.last_response.headers)

        client.send_request(self.request_template.format("GET"), "200")
        self.assertIn("age", client.last_response.headers)

        srv.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Connection: keep-alive\r\n"
            + "Content-Length: 13\r\n"
            + "Content-Type: text/html\r\n"
            + "Server: Deproxy Server\r\n"
            + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + "Cache-Control: private\r\n"
            + "\r\n"
            + "<html></html>"
        )

        client.send_request(
            self.request_template_x_tempesta_cache.format("PURGE", "GET"),
            "200",
        )
        self.assertIn("cache-control", client.last_response.headers)

        client.send_request(self.request_template.format("GET"), "200")
        self.assertNotIn("age", client.last_response.headers)

        client.send_request(self.request_template.format("GET"), "200")
        self.assertNotIn("age", client.last_response.headers)

        checks.check_tempesta_cache_stats(
            self.get_tempesta(),
            cache_hits=1,
            cache_misses=3,
            cl_msg_served_from_cache=1,
        )
        self.assertEqual(len(srv.requests), 4, "Server has lost requests.")


class TestPurgeGet(TempestaTest):
    backends = [
        # /server-1: default transfer encoding
        {
            "id": "default",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                "From: /server1\r\n"
                "Content-length: 9\r\n"
                "\r\n"
                "test-data"
            ),
        },
        # /server-2: chunked transfer encoding
        {
            "id": "chunked",
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                "From: /server2\r\n"
                "Transfer-Encoding: chunked\r\n"
                "\r\n"
                "9\r\n"
                "test-data\r\n"
                "0\r\n"
                "\r\n"
            ),
        },
        # /server-3: keepalive with chunked transfer encoding
        {
            "id": "chunked_keepalive",
            "type": "deproxy",
            "port": "8002",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                "From: /server3\r\n"
                "Transfer-Encoding: chunked\r\n"
                "Connection: Keep-Alive\r\n"
                "\r\n"
                "9\r\n"
                "test-data\r\n"
                "0\r\n"
                "\r\n"
            ),
        },
    ]

    tempesta = {
        "config": """
        listen 80;
        cache_purge;
        cache_purge_acl ${client_ip};

        frang_limits {
          http_methods GET PURGE;
        }

        srv_group sg1 { server ${server_ip}:8000; }
        srv_group sg2 { server ${server_ip}:8001; }
        srv_group sg3 { server ${server_ip}:8002; }

        vhost server1 { proxy_pass sg1; }
        vhost server2 { proxy_pass sg2; }
        vhost server3 { proxy_pass sg3; }

        http_chain {
          uri == "/server1" -> server1;
          uri == "/server2" -> server2;
          uri == "/server3" -> server3;
        }
        """
    }
    clients = [
        {"id": "purge", "type": "curl", "cmd_args": "--request PURGE --max-time 2"},
        {
            "id": "purge_get",
            "type": "curl",
            "headers": {
                "X-Tempesta-Cache": "get",
            },
            "cmd_args": "--request PURGE --max-time 2",
        },
    ]

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections(1))

    def test_purge_get_success(self):
        """Test that PURGE+GET request completed with no errors.
        (see Tempesta issue #1692)
        """
        self.start_all()
        client = self.get_client("purge_get")

        for uri in "/server1", "/server2", "/server3":
            with self.subTest("PURGE+GET", uri=uri):
                client.set_uri(uri)

                client.start()
                self.wait_while_busy(client)
                client.stop()
                response = client.last_response

                self.assertEqual(response.status, 200, response)
                # Response is from expected backend
                self.assertEqual(response.headers["from"], uri)
                # Body is truncated
                self.assertFalse(response.stdout)
                self.assertEqual(response.headers["content-length"], "0")
                # Purge is completed with no errors
                self.assertFalse(response.stderr)

    def test_purge_without_get_completed_with_no_warnings(self):
        self.start_all()
        client = self.get_client("purge")
        client.set_uri("/server1")

        client.start()
        self.wait_while_busy(client)
        client.stop()
        response = client.last_response

        self.assertEqual(response.status, 200, response)
        self.assertTrue(
            self.oops.find(dmesg.WARN_GENERIC, cond=dmesg.amount_zero), f"Some warnings were found"
        )
