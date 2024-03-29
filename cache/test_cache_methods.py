"""Functional tests of caching different methods."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2024 Tempesta Technologies, Inc."
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


class TestCacheMethods(TempestaTest):
    """There are checks for tempesta config - 'cache_methods [method];'."""

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
""",
    }

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "",
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

    response_no_content: str = (
        "HTTP/1.1 204 No Content\r\n"
        + "Connection: keep-alive\r\n"
        + "Server: Deproxy Server\r\n"
        + f"Date: {HttpMessage.date_time_string()}\r\n"
        + "\r\n"
    )

    messages = 10
    should_be_cached = True

    @staticmethod
    def generate_request(method):
        return (
            f"{method} /page.html HTTP/1.1\r\n"
            + "Host: {0}\r\n".format(tf_cfg.cfg.get("Client", "hostname"))
            + "Connection: keep-alive\r\n"
            + "Accept: */*\r\n"
            + "\r\n"
        )

    def check_tempesta_stats_and_response(self, client):
        """Check tempesta cache stats and 'age' header in responses."""
        tempesta: Tempesta = self.get_tempesta()
        tempesta.get_stats()
        srv: StaticDeproxyServer = self.get_server("deproxy")

        if self.should_be_cached:
            checks.check_tempesta_cache_stats(
                tempesta,
                cache_hits=self.messages - 1,
                cache_misses=1,
                cl_msg_served_from_cache=self.messages - 1,
            )
            self.assertEqual(
                len(srv.requests) and tempesta.stats.srv_msg_received,
                1,
                "Server has received unexpected number of requests.",
            )
        else:
            checks.check_tempesta_cache_stats(
                tempesta,
                cache_hits=0,
                cache_misses=0,
                cl_msg_served_from_cache=0,
            )
            self.assertEqual(
                len(srv.requests) and tempesta.stats.srv_msg_received,
                self.messages,
                "Server has received fewer requests than expected.",
            )

        self.assertNotIn("age", client.responses[0].headers)

        for response in client.responses[1:]:
            if self.should_be_cached:
                self.assertIn("age", response.headers)
            else:
                self.assertNotIn("age", response.headers)

    def _test(
        self,
        method: str,
        server_response: str,
    ):
        """Send some requests. Checks that repeated requests has/hasn't been cached."""
        if self.should_be_cached:
            cache_method = method
        else:
            cache_method = "HEAD" if method == "GET" else "GET"

        tempesta: Tempesta = self.get_tempesta()
        tempesta.config.defconfig += f"cache_methods {cache_method};\n"
        self.start_all_services()

        srv: StaticDeproxyServer = self.get_server("deproxy")
        srv.set_response(server_response)

        client: DeproxyClient = self.get_client("deproxy")
        for _ in range(self.messages):
            client.make_request(self.generate_request(method))
            client.wait_for_response(timeout=1)

        self.assertEqual(
            self.messages,
            len(client.responses),
            "Client has lost responses.",
        )
        self.check_tempesta_stats_and_response(client)

    def test_get(self):
        self._test(
            method="GET",
            server_response=RESPONSE_OK_EMPTY,
        )

    def test_post(self):
        self._test(
            method="POST",
            server_response=self.response_no_content,
        )

    def test_copy(self):
        self._test(
            method="COPY",
            server_response=RESPONSE_OK_EMPTY,
        )

    def test_delete(self):
        self._test(
            method="DELETE",
            server_response=self.response_no_content,
        )

    def test_head(self):
        self._test(
            method="HEAD",
            server_response=RESPONSE_OK_EMPTY,
        )

    def test_lock(self):
        self._test(
            method="LOCK",
            server_response=RESPONSE_OK_EMPTY,
        )

    def test_mkcol(self):
        self._test(
            method="MKCOL",
            server_response=RESPONSE_OK_EMPTY,
        )

    def test_move(self):
        self._test(
            method="MOVE",
            server_response=RESPONSE_OK_EMPTY,
        )

    def test_options(self):
        self._test(
            method="OPTIONS",
            server_response=RESPONSE_OK_EMPTY,
        )

    def test_patch(self):
        self._test(
            method="PATCH",
            server_response=RESPONSE_OK_EMPTY,
        )

    def test_propfind(self):
        self._test(
            method="PROPFIND",
            server_response=RESPONSE_OK_EMPTY,
        )

    def test_proppatch(self):
        self._test(
            method="PROPPATCH",
            server_response=RESPONSE_OK_EMPTY,
        )

    def test_put(self):
        self._test(
            method="PUT",
            server_response=self.response_no_content,
        )

    def test_trace(self):
        self._test(
            method="TRACE",
            server_response=RESPONSE_OK_EMPTY,
        )

    def test_unlock(self):
        self._test(
            method="UNLOCK",
            server_response=RESPONSE_OK_EMPTY,
        )


class TestCacheMethodsNoCache(TestCacheMethods):
    """Parametrization of tests in TestCacheMethods class."""

    should_be_cached = False


class TestCacheMethodsH2(TestCacheMethods):
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
