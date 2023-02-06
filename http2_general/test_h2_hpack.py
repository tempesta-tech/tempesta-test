"""Functional tests for HPACK."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

import time
from ssl import SSLWantWriteError

from h2.connection import AllowedStreamIDs, ConnectionInputs
from h2.errors import ErrorCodes
from h2.exceptions import ProtocolError
from h2.stream import StreamInputs
from hpack import HeaderTuple, NeverIndexedHeaderTuple
from hyperframe.frame import HeadersFrame

from framework import deproxy_client
from http2_general.helpers import H2Base


class TestHpack(H2Base):
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
        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")
        server = self.get_server("deproxy")

        new_table_size = 512
        client.update_initiate_settings(header_table_size=new_table_size)

        header = "x" * new_table_size * 2
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            "Server: Debian\r\n"
            "Date: test\r\n"
            f"x: {header}\r\n"
            "Content-Length: 0\r\n"
            "\r\n"
        )

        client.request_buffers.append(client.h2_connection.data_to_send())
        client.nrreq += 1

        client.wait_for_ack_settings()

        # Tempesta must not save large header in dynamic table.
        client.send_request(request=self.post_request, expected_status_code="200")

        # Client received large header as plain text.
        client.send_request(request=self.post_request, expected_status_code="200")
        self.assertNotIn(
            b"2.0 tempesta_fw (Tempesta FW pre-0.7.0)",
            client.response_buffer,
            "Tempesta does not encode via header as expected.",
        )
        self.assertIn(
            header.encode(),
            client.response_buffer,
            "Tempesta encode large header, but HEADER_TABLE_SIZE smaller than this header.",
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
        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")
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

        client.methods.append("POST")
        client.request_buffers.append(
            # \xbe - link to first index in dynamic table
            b"\x00\x00\x0c\x01\x05\x00\x00\x00\x05\x11\x86\xa0\xe4\x1d\x13\x9d\t\x84\x87\x83\xbe"
        )
        # increment counter to call handle_write method
        client.nrreq += 1
        client.valid_req_num += 1
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
        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")
        server = self.get_server("deproxy")
        client.parsing = False

        # Tempesta rewrites headers in dynamic table and saves 4064 bytes header last.
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            f"qwerty: {'x' * 4058}\r\n"
            "Content-Length: 0\r\n"
            "Date: test\r\n"
            "\r\n"
        )

        client.send_request(request=self.get_request, expected_status_code="200")

        # Second request must contain all response headers as new indexed field
        # because they will be rewritten in table in cycle.
        client.send_request(request=self.get_request, expected_status_code="200")

        for header in (
            b"2.0 tempesta_fw (Tempesta FW pre-0.7.0)",  # Via header
            b"Tempesta FW/pre-0.7.0",  # Server header
            b"test",  # Date header
            b"x" * 4058,  # optional header
        ):
            self.assertIn(
                header,
                client.response_buffer,
                "Tempesta does not encode via header as expected.",
            )

    def test_clearing_dynamic_table(self):
        """
        "an attempt to add an entry larger than the maximum size causes the table
        to be emptied of all existing entries and results in an empty table."
        RFC 7541 4.4
        """
        self.start_all_services()
        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")
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

        client.methods.append("POST")
        client.request_buffers.append(
            # \xbe - link to first index in table
            b"\x00\x00\x0c\x01\x05\x00\x00\x00\x05\x11\x86\xa0\xe4\x1d\x13\x9d\t\x84\x87\x83\xbe"
        )
        # increment counter to call handle_write method
        client.nrreq += 1
        client.valid_req_num += 1

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
        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")

        # Tempesta forwards response with via header and saves it in dynamic table.
        client.send_request(request=self.post_request, expected_status_code="200")
        self.assertIn(b"2.0 tempesta_fw (Tempesta FW pre-0.7.0)", client.response_buffer)

        # Tempesta forwards header from dynamic table. Via header is indexed.
        client.send_request(request=self.post_request, expected_status_code="200")
        self.assertNotIn(b"2.0 tempesta_fw (Tempesta FW pre-0.7.0)", client.response_buffer)

        # Tempesta MUST clear dynamic table when receive SETTINGS_HEADER_TABLE_SIZE = 0
        client.send_settings_frame(header_table_size=0)
        self.assertTrue(client.wait_for_ack_settings())

        client.send_settings_frame(header_table_size=4096)
        self.assertTrue(client.wait_for_ack_settings())

        # Tempesta MUST saves via header in dynamic table again. Via header is indexed again.
        client.send_request(request=self.post_request, expected_status_code="200")
        self.assertIn(b"2.0 tempesta_fw (Tempesta FW pre-0.7.0)", client.response_buffer)

        # Tempesta forwards header from dynamic table again.
        client.send_request(request=self.post_request, expected_status_code="200")
        self.assertNotIn(b"2.0 tempesta_fw (Tempesta FW pre-0.7.0)", client.response_buffer)

    def test_settings_header_table_stress(self):
        client, server = self.__setup_settings_header_table_tests()

        for new_table_size in range(128, 0, -1):
            header = "x" * new_table_size * 2
            server.set_response(
                "HTTP/1.1 200 OK\r\n"
                "Server: Debian\r\n"
                "Date: test\r\n"
                f"x: {header}\r\n"
                "Content-Length: 0\r\n"
                "\r\n"
            )
            self.__change_header_table_size_and_send_request(client, new_table_size, header)

        for new_table_size in range(0, 128, 1):
            header = "x" * new_table_size * 2
            server.set_response(
                "HTTP/1.1 200 OK\r\n"
                "Server: Debian\r\n"
                "Date: test\r\n"
                f"x: {header}\r\n"
                "Content-Length: 0\r\n"
                "\r\n"
            )
            self.__change_header_table_size_and_send_request(client, new_table_size, header)

    def test_hpack_bomb(self):
        """
        A HPACK bomb request causes the connection to be torn down with the
        error code ENHANCE_YOUR_CALM.
        """
        self.start_all_services(client=False)
        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")
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
                )

                # wait for tempesta to save header in dynamic table
                time.sleep(0.5)

                # Generate and send attack frames. It repeatedly refers to the first entry for 16kB.
                now = time.time()
                while now + 10 > time.time():
                    client.stream_id += 2
                    attack_frame = HeadersFrame(
                        stream_id=client.stream_id,
                        data=b"\xbe" * bomb_size,  # max window size 16384
                    )
                    attack_frame.flags.add("END_HEADERS")

                    try:
                        client.send(attack_frame.serialize())
                    except SSLWantWriteError:
                        continue

                # Make sure connection is closed by Tempesta.
                with self.assertRaises(ProtocolError):
                    client.stream_id = 1
                    client.make_request(request="asd", end_stream=True)

    def __setup_settings_header_table_tests(self):
        self.start_all_services()
        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")
        server = self.get_server("deproxy")

        client.update_initiate_settings()
        client.send_bytes(client.h2_connection.data_to_send())
        client.wait_for_ack_settings()

        return client, server

    def __change_header_table_size_and_send_request(self, client, new_table_size, header):
        client.send_settings_frame(header_table_size=new_table_size)
        client.wait_for_ack_settings()

        client.send_request(request=self.post_request, expected_status_code="200")
        client.send_request(request=self.post_request, expected_status_code="200")

        self.assertIn(
            header.encode(),
            client.response_buffer,
            "Tempesta encode large header, but HEADER_TABLE_SIZE smaller than this header.",
        )


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
        stream = client.h2_connection._get_or_create_stream(
            client.stream_id, AllowedStreamIDs(client.h2_connection.config.client_side)
        )
        stream.state_machine.process_input(StreamInputs.SEND_HEADERS)
        stream.state_machine.process_input(StreamInputs.SEND_END_STREAM)

        # add method in list to escape IndexError
        client.methods.append("POST")
        client.send_bytes(data, True)
        client.wait_for_response(1)

    def test_small_frame_payload_length(self):
        self.start_all_services()
        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")

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
        client.wait_for_response(0.5)

        # Client will be blocked because Tempesta received extra bytes
        self.assertTrue(client.connection_is_closed())
        self.assertIn(ErrorCodes.FRAME_SIZE_ERROR, client.error_codes)

    def test_large_frame_payload_length(self):
        self.start_all_services()
        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")

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

        self.assertTrue(client.connection_is_closed())
        self.assertIn(ErrorCodes.PROTOCOL_ERROR, client.error_codes)

    def test_invalid_data(self):
        self.start_all_services()
        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")

        client.update_initiate_settings()
        client.send_bytes(client.h2_connection.data_to_send())

        # send headers frame with stream_id = 1, header count = 3
        # and headers bytes - \x09\x02\x00 (invalid bytes)
        self.__make_request(client, b"\x00\x00\x03\x01\x05\x00\x00\x00\x01\x09\x02\x00")

        self.assertEqual(client.last_response.status, "400")
        self.assertTrue(client.connection_is_closed())
