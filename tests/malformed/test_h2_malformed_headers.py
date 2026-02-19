__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import unittest

from tests.malformed import test_malformed_headers


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

    async def test_upgrade(self):
        await self.common_check(headers=("Upgrade", "invalid"))

    async def test_te(self):
        await self.common_check(headers=("TE", "invalid"))

    async def test_expect(self):
        """TempestaFW blocks h2 requests with Expect header."""
        await self.common_check(headers=("Expect", "100-continue"))

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

    @unittest.SkipTest
    async def test_upgrade(self):
        pass

    @unittest.SkipTest
    async def test_te(self):
        pass

    @unittest.SkipTest
    async def test_expect(self):
        """This test move to H2MalformedRequestsTest."""

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
