"""Tests for Frang directive `http_trailer_split_allowed`."""
from framework import tester
from helpers import dmesg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

COUNT_WARNINGS_OK = 1


ERROR_MSG = "Frang limits warning is not shown"

RESPONSE_CONTENT = """HTTP/1.1 200 OK\r
Content-Length: 0\r\n
Connection: keep-alive\r\n\r\n
"""

TEMPESTA_CONF_ON = """
cache 0;
listen 80;


frang_limits {
    http_trailer_split_allowed true;
}


server ${server_ip}:8000;
"""

TEMPESTA_CONF_OFF = """
cache 0;
listen 80;


server ${server_ip}:8000;
"""

WARN = "frang: HTTP field appear in header and trailer"

ACCEPTED_REQUESTS_LIMIT_ON = (
    "POST / HTTP/1.1\r\n"
    "Host: debian\r\n"
    "Transfer-Encoding: gzip, chunked\r\n"
    "\r\n"
    "4\r\n"
    "test\r\n"
    "0\r\n"
    "HdrTest: testVal\r\n"
    "\r\n"
    "GET / HTTP/1.1\r\n"
    "Host: debian\r\n"
    "HdrTest: testVal\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "4\r\n"
    "test\r\n"
    "0\r\n"
    "\r\n"
    "POST / HTTP/1.1\r\n"
    "Host: debian\r\n"
    "HdrTest: testVal\r\n"
    "\r\n"
)
NOT_ACCEPTED_REQUEST_LIMIT_ON = (
    "GET / HTTP/1.1\r\n"
    "Host: debian\r\n"
    "HdrTest: testVal\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "4\r\n"
    "test\r\n"
    "0\r\n"
    "HdrTest: testVal\r\n"
    "\r\n"
)


class FrangHttpTrailerSplitLimitOnTestCase(tester.TempestaTest):

    clients = [
        {
            "id": "client",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    backends = [
        {
            "id": "0",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": RESPONSE_CONTENT,
        },
    ]

    tempesta = {
        "config": TEMPESTA_CONF_ON,
    }

    def setUp(self):
        """Set up test."""
        super().setUp()
        self.klog = dmesg.DmesgFinder(ratelimited=False)

    def start_all(self):
        """Start all requirements."""
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        srv = self.get_server("0")
        self.assertTrue(
            srv.wait_for_connections(timeout=1),
        )

    def test_accepted_request(self):
        self.start_all()

        deproxy_cl = self.get_client("client")
        deproxy_cl.start()
        deproxy_cl.make_requests(
            ACCEPTED_REQUESTS_LIMIT_ON,
        )
        deproxy_cl.wait_for_response(1)
        self.assertEqual(
            3,
            len(deproxy_cl.responses),
        )
        assert list(p.status for p in deproxy_cl.responses) == ["200"] * 3
        self.assertFalse(
            deproxy_cl.connection_is_closed(),
        )

    def test_not_accepted_request(self):
        self.start_all()

        deproxy_cl = self.get_client("client")
        deproxy_cl.start()
        deproxy_cl.make_requests(
            NOT_ACCEPTED_REQUEST_LIMIT_ON,
        )
        deproxy_cl.wait_for_response()

        self.assertEqual(
            0,
            len(deproxy_cl.responses),
        )
        self.assertTrue(
            deproxy_cl.connection_is_closed(),
        )
        self.assertEqual(
            self.klog.warn_count(WARN),
            COUNT_WARNINGS_OK,
            ERROR_MSG,
        )


class FrangHttpTrailerSplitLimitOffTestCase(tester.TempestaTest):
    """
    Accept all requests
    """

    clients = [
        {
            "id": "client",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    backends = [
        {
            "id": "0",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": RESPONSE_CONTENT,
        },
    ]

    tempesta = {
        "config": TEMPESTA_CONF_OFF,
    }

    def setUp(self):
        """Set up test."""
        super().setUp()
        self.klog = dmesg.DmesgFinder(ratelimited=False)

    def start_all(self):
        """Start all requirements."""
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        srv = self.get_server("0")
        self.assertTrue(
            srv.wait_for_connections(timeout=1),
        )

    def test_accepted_request(self):
        self.start_all()

        deproxy_cl = self.get_client("client")
        deproxy_cl.start()
        deproxy_cl.make_requests(
            ACCEPTED_REQUESTS_LIMIT_ON + NOT_ACCEPTED_REQUEST_LIMIT_ON,
        )
        deproxy_cl.wait_for_response(1)
        self.assertEqual(
            4,
            len(deproxy_cl.responses),
        )
        assert list(p.status for p in deproxy_cl.responses) == ["200"] * 4
        self.assertFalse(
            deproxy_cl.connection_is_closed(),
        )
