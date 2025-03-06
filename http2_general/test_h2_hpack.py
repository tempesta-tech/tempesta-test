"""Functional tests for HPACK."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import itertools
import time

from h2.connection import AllowedStreamIDs, ConnectionInputs
from h2.errors import ErrorCodes
from h2.stream import StreamInputs
from hpack import HeaderTuple, NeverIndexedHeaderTuple
from hpack.hpack import encode_integer
from hyperframe import frame
from hyperframe.frame import HeadersFrame

import helpers
from framework.deproxy_client import DeproxyClientH2, HuffmanEncoder
from helpers import tf_cfg
from helpers.control import Tempesta
from helpers.deproxy import HttpMessage
from http2_general.helpers import H2Base
from test_suite import marks


class TestHpackBase(H2Base):
    def change_header_table_size(self, client, new_table_size):
        client.send_settings_frame(header_table_size=new_table_size)
        client.wait_for_ack_settings()

    def setup_settings_header_table_tests(self):
        self.start_all_services()
        client: DeproxyClientH2 = self.get_client("deproxy")
        server = self.get_server("deproxy")

        client.update_initial_settings()
        client.send_bytes(client.h2_connection.data_to_send())
        client.wait_for_ack_settings()

        return client, server

    def change_header_table_size_and_send_request(self, client, new_table_size, header):
        self.change_header_table_size(client, new_table_size)

        client.send_request(request=self.post_request, expected_status_code="200")
        client.send_request(request=self.post_request, expected_status_code="200")

        self.assertTrue(
            client.check_header_presence_in_last_response_buffer(
                header.encode(),
            ),
            "Tempesta encode large header, but HEADER_TABLE_SIZE smaller than this header.",
        )


class TestHpack(TestHpackBase):
    def test_static_table(self):
        """
        Send request with headers from static table.
        Client should receive response with 200 status.
        """
        self.start_all_services()

        client = self.get_client("deproxy")
        client.send_request(
            request=[
                HeaderTuple(":authority", "example.com"),
                HeaderTuple(":path", "/"),
                HeaderTuple(":scheme", "https"),
                HeaderTuple(":method", "GET"),
                HeaderTuple("host", "example.com"),
            ],
            expected_status_code="200",
        )

    def test_never_indexed(self):
        """
        Send request with headers as plain text (no static table).
        Client should receive response with 200 status.
        """
        self.start_all_services()

        client = self.get_client("deproxy")
        client.send_request(
            request=[
                NeverIndexedHeaderTuple(":authority", "example.com"),
                NeverIndexedHeaderTuple(":path", "/"),
                NeverIndexedHeaderTuple(":scheme", "https"),
                NeverIndexedHeaderTuple(":method", "GET"),
                NeverIndexedHeaderTuple("host", "example.com"),
            ],
            expected_status_code="200",
        )

    def test_disable_huffman(self):
        """
        Send request without Huffman encoder. Huffman is enabled by default for H2Connection.
        Client should receive response with 200 status.
        """
        self.start_all_services()

        client = self.get_client("deproxy")
        client.parsing = False

        client = self.get_client("deproxy")
        client.make_request(
            self.post_request + [("host", "example.com")],
            end_stream=True,
            huffman=False,
        )
        self.assertTrue(client.wait_for_response())
        self.assertEqual(client.last_response.status, "200")

    def test_settings_header_table_size(self):
        """
        Client sets non-default value for SETTINGS_HEADER_TABLE_SIZE.
        Tempesta must not encode headers larger than set size.
        """
        self.start_all_services()
        client: DeproxyClientH2 = self.get_client("deproxy")
        server = self.get_server("deproxy")

        new_table_size = 512
        client.update_initial_settings(header_table_size=new_table_size)

        header = "x" * new_table_size * 2
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            "Server: Debian\r\n"
            f"Date: {HttpMessage.date_time_string()}\r\n"
            f"x: {header}\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )

        client.send_bytes(client.h2_connection.data_to_send())
        client.wait_for_ack_settings()

        # Tempesta must not save large header in dynamic table.
        client.send_request(request=self.post_request, expected_status_code="200")

        # Client received large header as plain text.
        client.send_request(request=self.post_request, expected_status_code="200")

        self.assertFalse(
            client.check_header_presence_in_last_response_buffer(
                f"2.0 tempesta_fw (Tempesta FW {helpers.tempesta.version()})".encode(),
            ),
            "Tempesta does not encode via header as expected.",
        )
        self.assertTrue(
            client.check_header_presence_in_last_response_buffer(
                header.encode(),
            ),
            "Tempesta encode large header, but HEADER_TABLE_SIZE smaller than this header.",
        )

    def test_relloc_hpack_table(self):
        """
        When count of entries in hpack dynamic table exceeded it's size
        Tempesta FW realloc hpack dynamic table. This test check it.
        """
        self.start_all_services()
        client: DeproxyClientH2 = self.get_client("deproxy")
        client.parsing = False

        headers = [
            HeaderTuple(":path", "/"),
            HeaderTuple(":scheme", "https"),
            HeaderTuple(":method", "POST"),
        ]

        for i in range(0, 125):
            for j in range(0, 26):
                key = ord("a") + j
                val = ord("a") + j

                first_indexed_header = [HeaderTuple(chr(key) * (125 - i), chr(val) * (125 - i))]
                client.send_request(
                    request=(
                        headers
                        + [NeverIndexedHeaderTuple(":authority", "localhost")]
                        + first_indexed_header
                    ),
                    expected_status_code="200",
                )

    def test_rewrite_dynamic_table_for_request(self):
        """
        "Before a new entry is added to the dynamic table, entries are evicted
        from the end of the dynamic table until the size of the dynamic table
        is less than or equal to (maximum size - new entry size) or until the
        table is empty."
        RFC 7541 4.4
        """
        self.start_all_services()
        client: DeproxyClientH2 = self.get_client("deproxy")
        client.parsing = False

        headers = [
            HeaderTuple(":path", "/"),
            HeaderTuple(":scheme", "https"),
            HeaderTuple(":method", "POST"),
        ]
        # send request with max size header in dynamic table
        # Tempesta MUST write header to table
        first_indexed_header = [HeaderTuple("a", "a" * 4063)]
        client.send_request(
            request=(
                headers
                + [NeverIndexedHeaderTuple(":authority", "localhost")]
                + first_indexed_header
            ),
            expected_status_code="200",
        )
        # send request with new incremental header
        # Tempesta MUST rewrite header to dynamic table.
        # Dynamic table does not have header from first request.
        second_indexed_header = [HeaderTuple("x", "x")]
        client.send_request(
            request=(
                headers
                + [NeverIndexedHeaderTuple(":authority", "localhost")]
                + second_indexed_header
            ),
            expected_status_code="200",
        )

        # We generate new stream with link to first index in dynamic table
        stream_id = 5
        stream = client.h2_connection._begin_new_stream(
            stream_id, AllowedStreamIDs(client.h2_connection.config.client_side)
        )
        stream.state_machine.process_input(StreamInputs.SEND_HEADERS)

        client.send_bytes(
            # \xbe - link to first index in dynamic table
            b"\x00\x00\x0c\x01\x05\x00\x00\x00\x05\x11\x86\xa0\xe4\x1d\x13\x9d\t\x84\x87\x83\xbe",
            expect_response=True,
        )
        self.assertTrue(client.wait_for_response())

        # Last forwarded request from Tempesta MUST have second indexed header
        server = self.get_server("deproxy")
        self.assertEqual(3, len(server.requests))
        self.assertIn(second_indexed_header[0], server.last_request.headers.items())
        self.assertNotIn(first_indexed_header[0], server.last_request.headers.items())

    def test_rewrite_dynamic_table_for_response(self):
        """
        "Before a new entry is added to the dynamic table, entries are evicted
        from the end of the dynamic table until the size of the dynamic table
        is less than or equal to (maximum size - new entry size) or until the
        table is empty."
        RFC 7541 4.4
        """
        self.start_all_services()
        client: DeproxyClientH2 = self.get_client("deproxy")
        server = self.get_server("deproxy")
        client.parsing = False

        date = HttpMessage.date_time_string()
        # Tempesta rewrites headers in dynamic table and saves 4064 bytes header last.
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            f"qwerty: {'x' * 4058}\r\n"
            "Content-Length: 0\r\n"
            f"Date: {date}\r\n"
            "\r\n"
        )

        client.send_request(request=self.get_request, expected_status_code="200")

        # Second request must contain all response headers as new indexed field
        # because they will be rewritten in table in cycle.
        client.send_request(request=self.get_request, expected_status_code="200")

        for header in (
            f"2.0 tempesta_fw (Tempesta FW {helpers.tempesta.version()})".encode(),  # Via header
            f"Tempesta FW/{helpers.tempesta.version()}".encode(),  # Server header
            date.encode(),  # Date header
            b"x" * 4058,  # optional header
        ):
            self.assertTrue(
                client.check_header_presence_in_last_response_buffer(
                    header,
                ),
                "Tempesta does not encode via header as expected.",
            )

    def test_clearing_dynamic_table(self):
        """
        "an attempt to add an entry larger than the maximum size causes the table
        to be emptied of all existing entries and results in an empty table."
        RFC 7541 4.4
        """
        self.start_all_services()
        client: DeproxyClientH2 = self.get_client("deproxy")
        client.parsing = False

        client.send_request(
            # Tempesta save header with 1k bytes in dynamic table.
            request=(self.get_request + [HeaderTuple("a", "a" * 1000)]),
            expected_status_code="200",
        )

        client.send_request(
            # Tempesta MUST clear dynamic table
            # because new indexed header is larger than 4096 bytes
            request=(self.get_request + [HeaderTuple("a", "a" * 6000)]),
            expected_status_code="200",
        )

        # We generate new stream with link to first index in dynamic table
        stream_id = 5
        stream = client.h2_connection._begin_new_stream(
            stream_id, AllowedStreamIDs(client.h2_connection.config.client_side)
        )
        stream.state_machine.process_input(StreamInputs.SEND_HEADERS)

        client.send_bytes(
            # \xbe - link to first index in table
            b"\x00\x00\x0c\x01\x05\x00\x00\x00\x05\x11\x86\xa0\xe4\x1d\x13\x9d\t\x84\x87\x83\xbe",
            expect_response=True,
        )

        self.assertTrue(client.wait_for_response())
        self.assertEqual(client.last_response.status, "400", "HTTP response status codes mismatch.")

    def test_clearing_dynamic_table_with_settings_frame(self):
        """
        "A change in the maximum size of the dynamic table is signaled via
        a dynamic table size update.
        This mechanism can be used to completely clear entries from the dynamic table by setting
        a maximum size of 0, which can subsequently be restored."
        RFC 7541 4.2
        """
        self.start_all_services()
        client: DeproxyClientH2 = self.get_client("deproxy")

        # Tempesta forwards response with via header and saves it in dynamic table.
        client.send_request(request=self.post_request, expected_status_code="200")
        self.assertTrue(
            client.check_header_presence_in_last_response_buffer(
                b"2.0 tempesta_fw (Tempesta FW " + helpers.tempesta.version().encode() + b")"
            )
        )

        # Tempesta forwards header from dynamic table. Via header is indexed.
        client.send_request(request=self.post_request, expected_status_code="200")
        self.assertFalse(
            client.check_header_presence_in_last_response_buffer(
                b"2.0 tempesta_fw (Tempesta FW " + helpers.tempesta.version().encode() + b")"
            )
        )

        # Tempesta MUST clear dynamic table when receive SETTINGS_HEADER_TABLE_SIZE = 0
        client.send_settings_frame(header_table_size=0)
        self.assertTrue(client.wait_for_ack_settings())

        client.send_settings_frame(header_table_size=4096)
        self.assertTrue(client.wait_for_ack_settings())

        # Tempesta MUST saves via header in dynamic table again. Via header is indexed again.
        client.send_request(request=self.post_request, expected_status_code="200")
        self.assertTrue(
            client.check_header_presence_in_last_response_buffer(
                b"2.0 tempesta_fw (Tempesta FW " + helpers.tempesta.version().encode() + b")"
            )
        )

        # Tempesta forwards header from dynamic table again.
        client.send_request(request=self.post_request, expected_status_code="200")
        self.assertFalse(
            client.check_header_presence_in_last_response_buffer(
                b"2.0 tempesta_fw (Tempesta FW " + helpers.tempesta.version().encode() + b")"
            )
        )

    def test_settings_header_table_stress(self):
        client, server = self.setup_settings_header_table_tests()

        for new_table_size in range(128, 0, -1):
            header = "x" * new_table_size * 2
            server.set_response(
                "HTTP/1.1 200 OK\r\n"
                "Server: Debian\r\n"
                f"Date: {HttpMessage.date_time_string()}\r\n"
                f"x: {header}\r\n"
                "Content-Length: 0\r\n"
                "\r\n"
            )
            self.change_header_table_size_and_send_request(client, new_table_size, header)

        for new_table_size in range(0, 128, 1):
            header = "x" * new_table_size * 2
            server.set_response(
                "HTTP/1.1 200 OK\r\n"
                "Server: Debian\r\n"
                f"Date: {HttpMessage.date_time_string()}\r\n"
                f"x: {header}\r\n"
                "Content-Length: 0\r\n"
                "\r\n"
            )
            self.change_header_table_size_and_send_request(client, new_table_size, header)

    def test_bytes_of_table_size_in_header_frame_1(self):
        """
        This dynamic table size update MUST occur at the beginning of the first header
        block following the change to the dynamic table size.
        RFC 7541 4.2
        """
        self.start_all_services()

        client = self.get_client("deproxy")
        error_msg = "Tempesta did not add dynamic table size ({0}) before first header block."

        # Client set HEADER_TABLE_SIZE = 1024 bytes and expected \x3f\xe1\x07
        # bytes in first header frame
        client.update_initial_settings(header_table_size=1024)
        client.send_request(request=self.post_request, expected_status_code="200")
        self.assertTrue(
            client.check_header_presence_in_last_response_buffer(b"\x3f\xe1\x07"),
            error_msg.format(1024),
        )
        self.assertEqual(client.h2_connection.decoder.header_table_size, 1024)

        # Client set HEADER_TABLE_SIZE = 12288 bytes, but Tempesta works with table 4096 bytes
        # and we expect \x3f\xe1\x07 bytes in first header frame
        client.send_settings_frame(header_table_size=12288)
        client.send_request(request=self.post_request, expected_status_code="200")
        self.assertTrue(
            client.check_header_presence_in_last_response_buffer(b"\x3f\xe1\x1f"),
            error_msg.format(4096),
        )
        self.assertEqual(client.h2_connection.decoder.header_table_size, 4096)

    def test_bytes_of_table_size_in_header_frame_2(self):
        """
        This dynamic table size update MUST occur at the beginning of the first header
        block following the change to the dynamic table size.
        RFC 7541 4.2
        """
        self.start_all_services()

        client = self.get_client("deproxy")

        # Client set HEADER_TABLE_SIZE = 12288 bytes, but Tempesta works with table 4096 bytes
        # and this default value for table size.
        # Therefore Tempesta does not return bytes of table size in header frame.
        client.update_initial_settings(header_table_size=12288)
        client.send_request(request=self.post_request, expected_status_code="200")
        self.assertFalse(
            client.check_header_presence_in_last_response_buffer(
                b"\x3f\xe1\x1f",
            ),
            "Tempesta added dynamic table size (4096) before first header block.",
        )
        self.assertEqual(client.h2_connection.decoder.header_table_size, 4096)

    def test_send_invalid_request_after_setting_header_table_size(self):
        """
        This dynamic table size update MUST occur at the beginning of the first header
        block following the change to the dynamic table size.
        RFC 7541 4.2
        """

        client, server = self.setup_settings_header_table_tests()

        # This test checks RFC 7541 4.2 for response on invalid request.
        self.change_header_table_size(client, 2048)
        client.send_request(
            request=[
                HeaderTuple(":authority", "bad.com"),
                HeaderTuple(":path", "/"),
                HeaderTuple(":scheme", "https"),
                HeaderTuple(":method", "GET"),
            ],
            expected_status_code="403",
        )
        self.assertEqual(client.h2_connection.decoder.header_table_size, 2048)

    def test_http_headers_code_charater_is_invalid_in_header(self):
        """
        This test checks that '1' is invalid character for http header data.
        It is necessary, because we lead on this fact in tempesta code, when
        we determine that skb contains headers.
        """
        client, server = self.setup_settings_header_table_tests()

        self.change_header_table_size(client, 2048)
        header = ("qwerty", chr(1) * 100)
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            "Server: Debian\r\n"
            f"Date: {HttpMessage.date_time_string()}\r\n"
            f"{header[0]}: {header[1]}\r\n"
            "Content-Length: 0\r\n\r\n"
        )

        client.send_request(request=self.post_request, expected_status_code="502")
        self.assertEqual(client.h2_connection.decoder.header_table_size, 2048)

    def test_big_header_after_setting_header_table_size(self):
        """
        This test checks RFC 7541 4.2 for a large header. This case
        needs a special test, since we split skb with large header.
        """
        client, server = self.setup_settings_header_table_tests()

        self.change_header_table_size(client, 2048)
        header = ("qwerty", "x" * 50000)
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            "Server: Debian\r\n"
            f"Date: {HttpMessage.date_time_string()}\r\n"
            f"{header[0]}: {header[1]}\r\n"
            "Content-Length: 0\r\n\r\n"
        )

        client.send_request(request=self.post_request, expected_status_code="200")
        self.assertIsNotNone(client.last_response.headers.get(header[0]))
        self.assertEqual(len(client.last_response.headers.get(header[0])), len(header[1]))
        self.assertEqual(client.h2_connection.decoder.header_table_size, 2048)

    def test_big_header_in_response(self):
        """Tempesta must forward header response with header > 64 KB."""
        header_size = 500000
        header = ("qwerty", "x" * header_size)
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        self.start_all_services()
        client.update_initial_settings(max_header_list_size=header_size * 2)

        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Server: Debian\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + f"{header[0]}: {header[1]}\r\n"
            + "Content-Length: 0\r\n\r\n"
        )

        client.send_request(request=self.post_request, expected_status_code="200")

        self.assertIsNotNone(client.last_response.headers.get(header[0]))
        self.assertEqual(len(client.last_response.headers.get(header[0])), len(header[1]))

    def test_big_header_and_body_in_response(self):
        """Tempesta must forward response with header and body > 64 KB."""
        size = 500000
        header = ("qwerty", "x" * size)
        response_body = "a" * 100000
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        self.start_all_services()
        client.update_initial_settings(max_header_list_size=size * 2)

        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Server: Debian\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + f"{header[0]}: {header[1]}\r\n"
            + f"Content-Length: {len(response_body)}\r\n\r\n"
            + response_body
        )

        client.send_request(request=self.post_request, expected_status_code="200")

        self.assertIsNotNone(client.last_response.headers.get(header[0]))
        self.assertEqual(len(client.last_response.headers.get(header[0])), len(header[1]))
        self.assertEqual(client.last_response.body, response_body)

    def test_get_method_as_string(self):
        """
        Client send request with method GET as string value.
        Request must be processed as usual.
        """
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        self.start_all_services()
        self.initiate_h2_connection(client)
        client.h2_connection.encoder.huffman = False

        client.h2_connection.send_headers(stream_id=1, headers=self.get_request, end_stream=True)
        client.send_bytes(
            data=b"\x00\x00\x14\x01\x05\x00\x00\x00\x01A\x0bexample.com\x84\x87B\x03GET",
            expect_response=True,
        )

        self.assertTrue(client.wait_for_response(3))
        self.assertEqual(client.last_response.status, "200")
        self.assertEqual(server.last_request.method, "GET")


class TestHpackStickyCookie(TestHpackBase):
    tempesta = {
        "config": """
            listen 443 proto=h2;
            srv_group default {
                server ${server_ip}:8000;
            }
            frang_limits {http_strict_host_checking false;}
            vhost v_good {
                proxy_pass default;
                sticky {
                    sticky_sessions;
                    cookie enforce;
                    secret "f00)9eR59*_/22";
                }
            }
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;
            cache 1;
            cache_fulfill * *;
            block_action attack reply;
            block_action error reply;
            http_chain {
                host == "bad.com"   -> block;
                host == "example.com" -> v_good;
            }
        """
    }

    def test_h2_cookie_after_setting_header_table_size(self):
        """
        This dynamic table size update MUST occur at the beginning of the first header
        block following the change to the dynamic table size.
        RFC 7541 4.2
        """
        client, server = self.setup_settings_header_table_tests()

        # This test checks RFC 7541 4.2 for response with cookie.
        self.change_header_table_size(client, 2048)
        client.send_request(request=self.post_request, expected_status_code="302")
        self.assertEqual(client.h2_connection.decoder.header_table_size, 2048)

        client.send_request(
            request=self.post_request
            + [HeaderTuple("Cookie", client.last_response.headers["set-cookie"])],
            expected_status_code="200",
        )


class TestHpackCache(TestHpackBase):
    tempesta = {
        "config": """
            listen 443 proto=h2;
            srv_group default {
                server ${server_ip}:8000;
            }
            frang_limits {http_strict_host_checking false;}
            vhost v_good {
                proxy_pass default;
            }
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;
            cache 1;
            cache_fulfill * *;
            cache_methods GET;
            block_action attack reply;
            block_action error reply;
            http_chain {
                host == "bad.com"   -> block;
                host == "example.com" -> v_good;
            }
        """
    }

    def test_h2_cache_304_after_setting_header_table_size(self):
        self.__test_h2_cache_after_setting_header_table_size("Mon, 12 Dec 2024 13:59:39 GMT", "304")

    def test_h2_cache_200_after_setting_header_table_size(self):
        self.__test_h2_cache_after_setting_header_table_size("Mon, 12 Dec 2020 13:59:39 GMT", "200")

    def test_cache_response_from_dynamic_table(self):
        """Tempesta must respond from cache to http2 client using hpack dynamic table."""
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + "Server: debian\r\n"
            + "x-my-hdr: value\r\n"
            + "Content-Length: 0\r\n\r\n"
        )

        self.start_all_services()
        self.initiate_h2_connection(client)

        client.send_request(self.get_request, "200")
        client.send_request(self.get_request, "200")

        self.assertEqual(1, len(server.requests))
        self._check_cached_response_from_dynamic_table(client)

    def test_cache_response_from_dynamic_table_for_different_client(self):
        """
        Tempesta must respond from cache to http2 client using hpack dynamic table.
        But Tempesta must return headers as text for new connection.
        """
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + "Server: debian\r\n"
            + "x-my-hdr: value\r\n"
            + "Content-Length: 0\r\n\r\n"
        )

        self.start_all_services()
        self.initiate_h2_connection(client)

        client.send_request(self.get_request, "200")
        client.stop()

        client.start()
        client.send_request(self.get_request, "200")

        self.assertEqual(1, len(server.requests))
        self._check_cached_response_as_text(client)

        client.send_request(self.get_request, "200")

        self.assertEqual(1, len(server.requests))
        self._check_cached_response_from_dynamic_table(client)

    def _check_cached_response_from_dynamic_table(self, client):
        self.assertIn("age", client.last_response.headers.keys())

        self.assertNotIn(
            b"x-my-hdr",
            client.last_response_buffer,
            "Tempesta return header key from cache as text, "
            "but bytes from the dynamic table were expected.",
        )
        self.assertNotIn(
            b"value",
            client.last_response_buffer,
            "Tempesta return header value from cache as text, "
            "but bytes from the dynamic table were expected.",
        )

    def _check_cached_response_as_text(self, client):
        self.assertIn("age", client.last_response.headers.keys())
        self.assertIn(
            b"x-my-hdr",
            client.last_response_buffer,
            "Tempesta return a cached response with header key as bytes from a dynamic table "
            "for a new connection, but the text were expected.",
        )
        self.assertIn(
            b"value",
            client.last_response_buffer,
            "Tempesta return a cached response with header value as bytes from a dynamic table "
            "for a new connection, but the text were expected.",
        )

    def __test_h2_cache_after_setting_header_table_size(self, date, status_code):
        """
        This dynamic table size update MUST occur at the beginning of the first header
        block following the change to the dynamic table size.
        RFC 7541 4.2
        """
        client, server = self.setup_settings_header_table_tests()

        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            "Server: Debian\r\n"
            "Date: Mon, 12 Dec 2021 13:59:39 GMT\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )

        headers = [
            HeaderTuple(":authority", "example.com"),
            HeaderTuple(":path", "/"),
            HeaderTuple(":scheme", "https"),
            HeaderTuple(":method", "GET"),
        ]

        client.send_request(request=headers, expected_status_code="200")

        # This test checks RFC 7541 4.2 for responses from cache with
        # different stus codes.
        self.change_header_table_size(client, 1024)
        headers.append(HeaderTuple("if-modified-since", date))
        client.send_request(request=headers, expected_status_code=status_code)
        self.assertEqual(client.h2_connection.decoder.header_table_size, 1024)


class TestFramePayloadLength(H2Base):
    """
    Additionally, an endpoint MAY use any applicable error code when it detects
    an error condition; a generic error code (such as PROTOCOL_ERROR or INTERNAL_ERROR)
    can always be used in place of more specific error codes.
    RFC 9113 5.4
    """

    @staticmethod
    def __make_request(client, data: bytes):
        # Create stream for H2Connection to escape error
        client.h2_connection.state_machine.process_input(ConnectionInputs.SEND_HEADERS)
        stream = client.init_stream_for_send(client.stream_id)
        stream.state_machine.process_input(StreamInputs.SEND_END_STREAM)

        # add method in list to escape IndexError
        client.methods.append("POST")
        client.send_bytes(data, True)
        client.wait_for_response(1)

    def test_small_frame_payload_length(self):
        self.start_all_services()
        client: DeproxyClientH2 = self.get_client("deproxy")

        # Tempesta and deproxy must save headers in dynamic table.
        client.send_request(self.get_request + [("asd", "qwe")], "200")

        # Tempesta return 200 response because extra bytes will be ignored.
        self.__make_request(
            client,
            # header count - 5, headers - 8.
            b"\x00\x00\x05\x01\x05\x00\x00\x00\x03\xbf\x84\x87\x82\xbe\xbe\xbe\xbe",
        )

        client.stream_id += 2
        client.make_request(self.get_request)

        # Client will be blocked because Tempesta received extra bytes
        self.assertTrue(client.wait_for_connection_close())
        self.assertIn(ErrorCodes.FRAME_SIZE_ERROR, client.error_codes)

    def test_large_frame_payload_length(self):
        self.start_all_services()
        client: DeproxyClientH2 = self.get_client("deproxy")

        # Tempesta and deproxy must save headers in dynamic table.
        client.send_request(self.get_request + [("asd", "qwe")], "200")

        # Tempesta does not return response because it does not receive all bytes.
        # Therefore, client must not wait for response.
        client.valid_req_num = 0
        self.__make_request(
            client,
            # header count - 7, headers - 5.
            b"\x00\x00\x07\x01\x05\x00\x00\x00\x03\xbf\x84\x87\x82\xbe",
        )

        client.stream_id += 2
        client.send_request(self.get_request, "400")

        self.assertTrue(client.wait_for_connection_close())
        self.assertIn(ErrorCodes.COMPRESSION_ERROR, client.error_codes)

    def test_invalid_data(self):
        self.start_all_services()
        client: DeproxyClientH2 = self.get_client("deproxy")

        client.update_initial_settings()
        client.send_bytes(client.h2_connection.data_to_send())

        # send headers frame with stream_id = 1, header count = 3
        # and headers bytes - \x09\x02\x00 (invalid bytes)
        self.__make_request(client, b"\x00\x00\x03\x01\x05\x00\x00\x00\x01\x09\x02\x00")

        self.assertEqual(client.last_response.status, "400")
        self.assertTrue(client.wait_for_connection_close())


SIZE_BYTES = encode_integer(10, 5)
SIZE_BYTES[0] |= 0x20


class TestHpackTableSizeEncodedInInvalidPlace(TestHpackBase):
    @marks.Parameterize.expand(
        [
            marks.Param(
                name="begin",
                data=bytes(SIZE_BYTES) + HuffmanEncoder().encode(H2Base.post_request),
                expected_status_code="200",
            ),
            marks.Param(
                name="middle",
                data=HuffmanEncoder().encode([(":authority", "example.com"), (":path", "/")])
                + bytes(SIZE_BYTES)
                + HuffmanEncoder().encode([(":scheme", "https"), (":method", "POST")]),
                expected_status_code="400",
            ),
            marks.Param(
                name="end",
                data=HuffmanEncoder().encode(H2Base.post_request) + bytes(SIZE_BYTES),
                expected_status_code="400",
            ),
        ]
    )
    def test(self, name, data, expected_status_code):
        """
        A change in the maximum size of the dynamic table is signaled
        via a dynamic table size update (see Section 6.3). This dynamic
        table size update MUST occur at the beginning of the first
        header block following the change to the dynamic table size.
        In HTTP/2, this follows a settings acknowledgment (see Section
        6.5.3 of [HTTP2]).
        In this test we send maximum size of the dynamic table in the
        middle and at the end of the of the first header block.
        """
        self.start_all_services()

        client = self.get_client("deproxy")
        self.initiate_h2_connection(client)

        stream = client.init_stream_for_send(client.stream_id)

        frame = None
        frame = HeadersFrame(
            stream_id=1,
            data=data,
            flags=["END_HEADERS", "END_STREAM"],
        )

        client.send_bytes(
            client.h2_connection.data_to_send() + frame.serialize(), expect_response=True
        )
        self.assertTrue(client.wait_for_response())
        self.assertEqual(client.last_response.status, expected_status_code)
        if expected_status_code != "200":
            self.assertIn(ErrorCodes.COMPRESSION_ERROR, client.error_codes)
            self.assertTrue(client.wait_for_connection_close())


class TestHpackBomb(TestHpackBase):
    tempesta = {
        "config": """
            listen 443 proto=h2;
            srv_group default {
                server ${server_ip}:8000;
            }
            vhost good {
                proxy_pass default;
            }
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;

            http_max_header_list_size 65536;

            block_action attack reply;
            block_action error reply;
            http_chain {
                host == "bad.com"   -> block;
                                    -> good;
            }
        """
    }

    @marks.Parameterize.expand(
        [marks.Param(name="huffman", huffman=True), marks.Param(name="no_huffman", huffman=False)]
    )
    def test_hpack_bomb(self, name, huffman):
        """
        A HPACK bomb request causes the connection to be torn down with the
        error code ENHANCE_YOUR_CALM.
        """
        self.start_all_services(client=False)
        client: DeproxyClientH2 = self.get_client("deproxy")
        client.parsing = False

        # Send 4096 byte header and save in dynamic table.
        # Max table size 4096 bytes, see RFC 7540 6.5.2
        for bomb_size in [(2**8), (2**14 - 9)]:
            with self.subTest(bomb_size=bomb_size):
                client.stop()
                client.start()
                client.make_request(
                    request=self.post_request + [HeaderTuple(b"a", b"a" * 4063)],
                    end_stream=False,
                    huffman=huffman,
                )

                # wait for tempesta to save header in dynamic table
                time.sleep(0.5)

                # Generate and send attack frames. It repeatedly refers to the first entry for 16kB.
                client.stream_id += 2
                stream = client.init_stream_for_send(client.stream_id)
                attack_frame = HeadersFrame(
                    stream_id=client.stream_id,
                    data=b"\xbe" * bomb_size,
                    flags=["END_HEADERS", "END_STREAM"],
                )

                client.send_bytes(data=attack_frame.serialize(), expect_response=True)
                self.assertTrue(client.wait_for_response())
                self.assertEqual(client.last_response.status, "403")
                self.assertTrue(client.wait_for_connection_close())
                self.assertIn(ErrorCodes.PROTOCOL_ERROR, client.error_codes)


class TestLoadingHeadersFromHpackDynamicTable(H2Base):
    """
    Some headers required special handling, when they are
    loaded from hpack dynamic table. This class checks how
    we handle this headers when we load them from hpack
    dynamic table.
    """

    tempesta = {
        "config": f"""
            listen 443 proto=h2;
            access_log dmesg;
            srv_group default {{
                server {tf_cfg.cfg.get("Server", "ip")}:8000;
            }}
            frang_limits {{http_strict_host_checking false;}}
            vhost good {{
                frang_limits {{
                    http_method_override_allowed false;
                }}
                http_post_validate;
                proxy_pass default;
            }}

            tls_certificate {tf_cfg.cfg.get("Tempesta", "workdir")}/tempesta.crt;
            tls_certificate_key {tf_cfg.cfg.get("Tempesta", "workdir")}/tempesta.key;
            tls_match_any_server_name;

            block_action attack reply;
            block_action error reply;
            http_chain {{
                host == \"bad.com\" -> block;
                                    -> good;
            }}
        """
    }

    tempesta_cache = {
        "config": f"""
            listen 443 proto=h2;
            access_log dmesg;
            srv_group default {{
                server {tf_cfg.cfg.get("Server", "ip")}:8000;
            }}
            frang_limits {{http_strict_host_checking false;}}
            vhost good {{
                frang_limits {{
                    http_method_override_allowed false;
                }}
                http_post_validate;
                proxy_pass default;
            }}

            cache 2;
            cache_fulfill * *;

            tls_certificate {tf_cfg.cfg.get("Tempesta", "workdir")}/tempesta.crt;
            tls_certificate_key {tf_cfg.cfg.get("Tempesta", "workdir")}/tempesta.key;
            tls_match_any_server_name;

            block_action attack reply;
            block_action error reply;
            http_chain {{
                host == \"bad.com\" -> block;
                                    -> good;
            }}
        """
    }

    tempesta_override_allowed = {
        "config": f"""
            listen 443 proto=h2;
            access_log dmesg;
            srv_group default {{
                server {tf_cfg.cfg.get("Server", "ip")}:8000;
            }}
            frang_limits {{http_strict_host_checking false;}}
            vhost good {{
                frang_limits {{
                    http_method_override_allowed true;
                    http_methods POST GET HEAD;
                }}
                http_post_validate;
                proxy_pass default;
            }}

            tls_certificate {tf_cfg.cfg.get("Tempesta", "workdir")}/tempesta.crt;
            tls_certificate_key {tf_cfg.cfg.get("Tempesta", "workdir")}/tempesta.key;
            tls_match_any_server_name;

            block_action attack reply;
            block_action error reply;
            http_chain {{
                host == \"bad.com\" -> block;
                                    -> good;
            }}
        """
    }

    def __check_server_resp(self, server, header, expected):
        for server_req in server.requests:
            val = server_req.headers[header]
            self.assertIsNotNone(val)
            self.assertEqual(val, expected)

    def __do_test_replacement(self, client, server, content_type, expected_content_type):
        number_of_whitespace_places = content_type.count("{}")

        for state in itertools.product(
            ["", " ", "\t", " \t", "\t "], repeat=number_of_whitespace_places
        ):
            request = client.create_request(
                method="POST",
                headers=[("content-type", content_type.format(*state))],
            )

            client.send_request(request, "200")
            self.__check_server_resp(server, "content-type", expected_content_type)

            client.send_request(request, "200")
            self.__check_server_resp(server, "content-type", expected_content_type)

    def test_content_length_field_from_hpack_table(self):
        self.start_all_services()
        client = self.get_client("deproxy")

        request = client.create_request(
            method="POST",
            headers=[("content-length", "10")],
            body="aaaaaaaaaa",
        )

        client.send_request(request, "200")
        client.send_request(request, "200")

    def test_content_type_from_hpack_table(self):
        self.disable_deproxy_auto_parser()
        self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        self.__do_test_replacement(
            client,
            server,
            'multiPART/form-data;{}boundary=helloworld{};{}o_param="123" ',
            "multipart/form-data; boundary=helloworld",
        )

    def test_method_override_from_hpack_table(self):
        self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        request = client.create_request(
            method="GET",
            headers=[("x-http-method-override", "HEAD")],
        )

        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(self.tempesta_override_allowed["config"])
        tempesta.reload()

        client.send_request(request, "200")

        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(self.tempesta["config"])
        tempesta.reload()

        client.send_request(request, "403")

    def test_pragma_from_hpack_table(self):
        self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        request = client.create_request(
            method="GET",
            headers=[("pragma", "no-cache")],
        )

        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(self.tempesta_cache["config"])
        tempesta.reload()

        client.send_request(request, "200")
        client.send_request(request, "200")
        self.assertEqual(2, len(server.requests))

        request = client.create_request(method="GET", headers=[])

        client.send_request(request, "200")
        self.assertEqual(3, len(server.requests))
        client.send_request(request, "200")
        self.assertEqual(3, len(server.requests))

    def __reload_tempesta_with_ja5h(self, ja5_config):
        tempesta: Tempesta = self.get_tempesta()
        tempesta.config.defconfig += ja5_config
        tempesta.reload()

    def test_referer_from_hpack_table(self):
        self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        request_hashed = client.create_request(
            method="GET",
            headers=[("referer", "http://tempesta-tech.com:8080")],
        )
        client.send_request(request_hashed, "200")

        last_response = self.loggers.dmesg.access_log_last_message()
        # Do not allow requests with same hash from the client.
        self.__reload_tempesta_with_ja5h(
            f"""
            ja5h {{
                hash {last_response.ja5h} 0 0;
            }}
        """
        )

        # Referer is false allow request
        request = client.create_request(method="GET", headers=[])
        client.send_request(request, "200")
        self.assertEqual(2, len(server.requests))

        # Request with same hash is blocked
        client.send_request(request_hashed, "403")
        self.assertEqual(2, len(server.requests))

    def __send_add_check_req_with_huffman(self, client, request, huffman, expected_status_code):
        # create stream and change state machine in H2Connection object
        stream = client.init_stream_for_send(client.stream_id)

        hf = frame.HeadersFrame(
            stream_id=client.stream_id,
            data=client.h2_connection.encoder.encode(request, huffman=huffman),
            flags=["END_HEADERS", "END_STREAM"],
        )
        client.send_bytes(data=hf.serialize(), expect_response=True)

        self.assertTrue(client.wait_for_response())
        self.assertEqual(client.last_response.status, expected_status_code)

        client.stream_id += 2

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="huffman_1",
                huffman=True,
                first_request=[
                    HeaderTuple(":authority", "localhost"),
                    HeaderTuple(":path", "/"),
                    HeaderTuple(":scheme", "https"),
                    HeaderTuple(":method", "GET"),
                    HeaderTuple("referer", "http://tempesta-tech.com:8080"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq"),
                    HeaderTuple("cookie", "kk=kkkkkkkkkkkkk"),
                    HeaderTuple("cookie", "q=qq; q=qqq; q=qqqq; q=qqqqq"),
                ],
                second_request=[
                    HeaderTuple(":authority", "localhost"),
                    HeaderTuple(":path", "/"),
                    HeaderTuple(":scheme", "https"),
                    HeaderTuple(":method", "GET"),
                    HeaderTuple("referer", "http://tempesta-tech.com:8080"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=bdsfds; dd=ddsfdsffds"),
                    HeaderTuple("cookie", "z=q; e=d"),
                ],
            ),
            marks.Param(
                name="no_huffman_1",
                huffman=False,
                first_request=[
                    HeaderTuple(":authority", "localhost"),
                    HeaderTuple(":path", "/"),
                    HeaderTuple(":scheme", "https"),
                    HeaderTuple(":method", "GET"),
                    HeaderTuple("referer", "http://tempesta-tech.com:8080"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq"),
                    HeaderTuple("cookie", "kk=kkkkkkkkkkkkk"),
                    HeaderTuple("cookie", "q=qq; q=qqq; q=qqqq; q=qqqqq"),
                ],
                second_request=[
                    HeaderTuple(":authority", "localhost"),
                    HeaderTuple(":path", "/"),
                    HeaderTuple(":scheme", "https"),
                    HeaderTuple(":method", "GET"),
                    HeaderTuple("referer", "http://tempesta-tech.com:8080"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=bdsfds; dd=ddsfdsffds"),
                    HeaderTuple("cookie", "z=q; e=d"),
                ],
            ),
            marks.Param(
                name="huffman_2",
                huffman=True,
                first_request=[
                    HeaderTuple(":authority", "localhost"),
                    HeaderTuple(":path", "/"),
                    HeaderTuple(":scheme", "https"),
                    HeaderTuple(":method", "GET"),
                    HeaderTuple("referer", "http://tempesta-tech.com:8080"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; l=ll"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; k=kk"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; zzz=zzzzz"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; b=bbb"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; t=tttt"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; o=oooo"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; u=uu"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; u=uu"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; i=ii"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; p=ppp"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; iii=iiiii"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; r=rr"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq"),
                    HeaderTuple("cookie", "qqq=qqqqqqqqqqqqqqqqq"),
                    HeaderTuple("cookie", "qqqq=qqqqqqqqqqqqqqqqq"),
                    HeaderTuple("cookie", "qqa=qqqqqqqqqqqqqqqa"),
                    HeaderTuple("cookie", "qqb=qqqqqqqqqqqqqqqb"),
                    HeaderTuple("cookie", "qqc=qqqqqqqqqqqqqqqc"),
                ],
                second_request=[
                    HeaderTuple(":authority", "localhost"),
                    HeaderTuple(":path", "/"),
                    HeaderTuple(":scheme", "https"),
                    HeaderTuple(":method", "GET"),
                    HeaderTuple("referer", "http://tempesta-tech.com:8080"),
                    HeaderTuple("cookie", "z=q; e=d"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=bdsfds; dd=ddsfdsffds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                ],
            ),
            marks.Param(
                name="no_huffman_2",
                huffman=True,
                first_request=[
                    HeaderTuple(":authority", "localhost"),
                    HeaderTuple(":path", "/"),
                    HeaderTuple(":scheme", "https"),
                    HeaderTuple(":method", "GET"),
                    HeaderTuple("referer", "http://tempesta-tech.com:8080"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; l=ll"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; k=kk"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; zzz=zzzzz"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; b=bbb"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; t=tttt"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; o=oooo"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; u=uu"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; u=uu"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; i=ii"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; p=ppp"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; iii=iiiii"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq; r=rr"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq"),
                    HeaderTuple("cookie", "qq=qqqqqqqqqqqqqqq"),
                    HeaderTuple("cookie", "qqq=qqqqqqqqqqqqqqqqq"),
                    HeaderTuple("cookie", "qqqq=qqqqqqqqqqqqqqqqq"),
                    HeaderTuple("cookie", "qqa=qqqqqqqqqqqqqqqa"),
                    HeaderTuple("cookie", "qqb=qqqqqqqqqqqqqqqb"),
                    HeaderTuple("cookie", "qqc=qqqqqqqqqqqqqqqc"),
                ],
                second_request=[
                    HeaderTuple(":authority", "localhost"),
                    HeaderTuple(":path", "/"),
                    HeaderTuple(":scheme", "https"),
                    HeaderTuple(":method", "GET"),
                    HeaderTuple("referer", "http://tempesta-tech.com:8080"),
                    HeaderTuple("cookie", "z=q; e=d"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=bdsfds; dd=ddsfdsffds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                    HeaderTuple("cookie", "a=b; dd=dfds"),
                ],
            ),
        ]
    )
    def test_cookie_from_hpack_table(self, name, huffman, first_request, second_request):
        self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        self.initiate_h2_connection(client)
        self.__send_add_check_req_with_huffman(client, first_request, huffman, "200")
        ja5h = self.loggers.dmesg.access_log_last_message().ja5h

        request_to_save_cookie_in_hpack = [
            HeaderTuple(":authority", "localhost"),
            HeaderTuple(":path", "/"),
            HeaderTuple(":scheme", "https"),
            HeaderTuple(":method", "GET"),
            HeaderTuple("referer", "http://tempesta-tech.com:8080"),
            HeaderTuple("cookie", "a=b; dd=dfds"),
            HeaderTuple("cookie", "a=bdsfds; dd=ddsfdsffds"),
        ]

        self.__send_add_check_req_with_huffman(
            client, request_to_save_cookie_in_hpack, huffman, "200"
        )

        # Block requests with refer and 'n' cookies
        self.__reload_tempesta_with_ja5h(
            f"""
            ja5h {{
                hash {ja5h} 0 0;
            }}
            """
        )

        # Cookie was reloaded from hpack table, count is 6 blocked.
        self.__send_add_check_req_with_huffman(client, second_request, huffman, "403")

        client.restart()
        self.initiate_h2_connection(client)

        # Request which was previously successful is blocked.
        self.__send_add_check_req_with_huffman(client, first_request, huffman, "403")
