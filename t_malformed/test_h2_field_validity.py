"""h2 tests for validating header fields. RFC 9113 8.2.1."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

import random

from framework import tester


class TestH2HeaderFieldRequest(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + "Date: test\r\n"
                + "Server: debian\r\n"
                + "Content-Length: 0\r\n\r\n"
            ),
        }
    ]

    tempesta = {
        "config": """
listen 443 proto=h2;
server ${server_ip}:8000;
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
        """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    def send_response_and_check_connection_is_closed(self, header: list):
        self.start_all_services()

        client = self.get_client("deproxy")
        client.parsing = False

        client.make_request(
            [
                (":authority", "example.com"),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
            ]
            + header,
            huffman=False,
        )
        self.assertTrue(client.wait_for_response())
        self.assertEqual("400", client.last_response.status)

        self.assertTrue(client.wait_for_connection_close())

    def test_ascii_uppercase_in_header_name(self):
        """
        A field name MUST NOT contain characters in the ranges 0x00-0x20, 0x41-0x5a,
        or 0x7f-0xff (all ranges inclusive). This specifically excludes all non-visible
        ASCII characters, ASCII SP (0x20), and uppercase characters
        ('A' to 'Z', ASCII 0x41 to 0x5a).
        RFC 9113 8.2.1
        """
        symbol = random.randint(0x41, 0x5A).to_bytes(1, "big")
        with self.subTest(symbol=symbol):
            self.send_response_and_check_connection_is_closed([(b"x-my-hdr" + symbol, b"value")])

    def test_ascii_from_0x7f_to_0xff_in_header_name(self):
        """
        A field name MUST NOT contain characters in the ranges 0x00-0x20, 0x41-0x5a,
        or 0x7f-0xff (all ranges inclusive). This specifically excludes all non-visible
        ASCII characters, ASCII SP (0x20), and uppercase characters
        ('A' to 'Z', ASCII 0x41 to 0x5a).
        RFC 9113 8.2.1
        """
        symbol = random.randint(0x7F, 0xFF).to_bytes(1, "big")
        with self.subTest(hex=symbol):
            self.send_response_and_check_connection_is_closed([(b"x-my-hdr" + symbol, b"value")])

    def test_ascii_from_0x00_to_0x20_in_header_name(self):
        """
        A field name MUST NOT contain characters in the ranges 0x00-0x20, 0x41-0x5a,
        or 0x7f-0xff (all ranges inclusive). This specifically excludes all non-visible
        ASCII characters, ASCII SP (0x20), and uppercase characters
        ('A' to 'Z', ASCII 0x41 to 0x5a).
        RFC 9113 8.2.1
        """
        for symbol in range(0x00, 0x20):
            symbol = symbol.to_bytes(1, "big")
            with self.subTest(hex=symbol):
                self.send_response_and_check_connection_is_closed(
                    [(b"x-my-hdr" + symbol, b"value")]
                )

    def test_ascii_0x00_0x0a_0x0d_in_header_value(self):
        """
        A field value MUST NOT contain the zero value (ASCII NUL, 0x00),
        line feed (ASCII LF, 0x0a), or carriage return (ASCII CR, 0x0d) at any position.
        RFC 9113 8.2.1
        """
        for symbol in [b"\x00", b"\x0a", b"\x0d"]:
            with self.subTest(symbol=symbol):
                self.send_response_and_check_connection_is_closed(
                    [(b"x-my-hdr", b"val" + symbol + b"ue")]
                )

    def test_ascii_0x20_and_0x09_in_header_value(self):
        """
        A field value MUST NOT start or end with an ASCII whitespace character
        (ASCII SP or HTAB, 0x20 or 0x09).
        RFC 9113 8.2.1
        """
        for symbol in [b"\x20", b"\x09"]:
            for header_value in [b"value" + symbol, symbol + b"value"]:
                with self.subTest(header_value=header_value, symbol=symbol):
                    self.send_response_and_check_connection_is_closed([(b"x-my-hdr", header_value)])


class TestH2HeaderFieldResponse(TestH2HeaderFieldRequest):
    def send_response_and_check_connection_is_closed(self, header: list):
        self.start_all_services()

        server = self.get_server("deproxy")
        server.set_response(
            b"HTTP/1.1 200 OK\r\n"
            + b"Date: test\r\n"
            + b"Server: debian\r\n"
            + header[0][0]
            + b": "
            + header[0][1]
            + b"\r\n"
            + b"Content-Length: 0\r\n\r\n"
        )

        client = self.get_client("deproxy")
        client.parsing = False

        client.send_request(
            [
                (":authority", "example.com"),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
            ],
            "502",
        )

    def test_ascii_uppercase_in_header_name(self):
        """Tempesta converts all characters to lowercase."""
        pass
