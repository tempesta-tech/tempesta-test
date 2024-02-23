"""Functional tests of caching different methods."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework.deproxy_client import DeproxyClient
from framework.deproxy_server import StaticDeproxyServer
from framework.tester import TempestaTest
from helpers import checks_for_tests as checks
from helpers import tf_cfg
from helpers.control import Tempesta
from helpers.deproxy import HttpMessage

RESPONSE_OK_EMPTY: str = (
    "HTTP/1.1 200 OK\r\n"
    + "Connection: keep-alive\r\n"
    + "Content-Length: 0\r\n"
    + "Server: Deproxy Server\r\n"
    + f"Date: {HttpMessage.date_time_string()}\r\n"
    + "\r\n"
)


class TestMultipleMethods(TempestaTest):
    """
    TempestaFW must return cached responses to exactly matching request
    methods only. I.e. if we receive HEAD requests, we must not return response
    cached for GET method.
    RFC 7234:
    The primary cache key consists of the request method and target URI.
    """

    tempesta = {
        "config": """
    listen 80;
    listen 443 proto=h2; 

    server ${server_ip}:8000;

    vhost default {
        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;
        proxy_pass default;
    }

    cache 2;
    cache_fulfill * *;
    cache_methods GET HEAD;
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
                + "<html><>/html"
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

    @staticmethod
    def generate_request(method):
        return (
            f"{method} /page.html HTTP/1.1\r\n"
            + "Host: {0}\r\n".format(tf_cfg.cfg.get("Client", "hostname"))
            + "Connection: keep-alive\r\n"
            + "Accept: */*\r\n"
            + "\r\n"
        )

    def test_caching_different_methods(self):
        """
        Send requests with different methods and checks that responses has been from different
        cache.
        """
        self.start_all_services()
        client: DeproxyClient = self.get_client("deproxy")
        srv: StaticDeproxyServer = self.get_server("deproxy")

        client.send_request(self.generate_request("GET"), "200")
        self.assertNotIn("age", client.last_response.headers)

        srv.set_response(RESPONSE_OK_EMPTY)

        client.send_request(self.generate_request("HEAD"), "200")
        self.assertIn("age", client.last_response.headers)

        client.send_request(self.generate_request("GET"), "200")
        response_get = client.last_response
        self.assertIn("age", client.last_response.headers)

        client.send_request(self.generate_request("HEAD"), "200")
        response_head = client.last_response
        self.assertIn("age", client.last_response.headers)

        self.assertEqual(
            response_get.headers["Content-Length"],
            response_head.headers["Content-Length"],
            "Responses has not received from a single cache.",
        )

        checks.check_tempesta_cache_stats(
            self.get_tempesta(),
            cache_hits=3,
            cache_misses=1,
            cl_msg_served_from_cache=3,
        )
        self.assertEqual(
            len(self.get_server("deproxy").requests),
            1,
            "Server has received unexpected number of requests.",
        )


class TestMultipleMethodsH2(TestMultipleMethods):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    @staticmethod
    def generate_request(method):
        return [
            (":authority", tf_cfg.cfg.get("Client", "hostname")),
            (":path", "/page.html"),
            (":scheme", "https"),
            (":method", method),
        ]


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
