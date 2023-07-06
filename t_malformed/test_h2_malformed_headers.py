__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

import unittest

from t_malformed import test_malformed_headers


class H2MalformedRequestsTest(test_malformed_headers.MalformedRequestsTest):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    def send_success_request(self):
        clnt = self.get_client("deproxy")
        clnt.send_request(
            [
                (":authority", "example.com"),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
            ],
            "200",
        )

    def test_upgrade(self):
        self.common_check(headers=("Upgrade", "invalid"))

    def test_te(self):
        self.common_check(headers=("TE", "invalid"))

    @staticmethod
    def generate_request(headers: tuple, method="GET"):
        if headers[0] == "Host":
            return [
                (":path", "/"),
                (":scheme", "https"),
                (":method", method),
                (":authority", headers[1]),
            ]
        else:
            return [
                (":path", "/"),
                (":scheme", "https"),
                (":method", method),
                (":authority", "localhost"),
                (headers[0].lower(), headers[1]),
            ]


@unittest.expectedFailure
class H2MalformedRequestsWithoutStrictParsingTest(
    test_malformed_headers.MalformedRequestsWithoutStrictParsingTest
):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    def send_success_request(self):
        clnt = self.get_client("deproxy")
        clnt.send_request(
            [
                (":authority", "example.com"),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
            ],
            "200",
        )

    @unittest.SkipTest
    def test_upgrade(self):
        pass

    @unittest.SkipTest
    def test_te(self):
        pass

    @staticmethod
    def generate_request(headers: tuple, method="GET"):
        return H2MalformedRequestsTest.generate_request(headers, method)


class H2MalformedResponsesTest(test_malformed_headers.MalformedResponsesTest):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]
    request = [
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
        (":authority", "localhost"),
    ]


@unittest.expectedFailure
class H2MalformedResponseWithoutStrictParsingTest(
    test_malformed_headers.MalformedResponseWithoutStrictParsingTest
):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]
    request = [
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
        (":authority", "localhost"),
    ]

    def send_success_request(self):
        clnt = self.get_client("deproxy")
        clnt.send_request(
            [
                (":authority", "example.com"),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
            ],
            "200",
        )


class H2EtagAlphabetTest(test_malformed_headers.EtagAlphabetTest):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]
    request = [
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
        (":authority", "localhost"),
    ]

    def send_success_request(self):
        clnt = self.get_client("deproxy")
        clnt.send_request(
            [
                (":authority", "example.com"),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
            ],
            "200",
        )


class H2EtagAlphabetBrangeTest(test_malformed_headers.EtagAlphabetBrangeTest):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]
    request = [
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
        (":authority", "localhost"),
    ]

    def send_success_request(self):
        clnt = self.get_client("deproxy")
        clnt.send_request(
            [
                (":authority", "example.com"),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
            ],
            "200",
        )
