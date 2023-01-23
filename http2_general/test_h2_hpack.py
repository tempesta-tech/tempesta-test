"""Functional tests for HPACK."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

import time
from ssl import SSLWantWriteError

import h2.connection
from h2.connection import AllowedStreamIDs
from h2.exceptions import ProtocolError
from h2.stream import StreamInputs
from hpack import HeaderTuple, NeverIndexedHeaderTuple
from hyperframe.frame import HeadersFrame

from framework import deproxy_client, deproxy_server, tester


class TestHpack(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        }
    ]

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
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
            [
                (":authority", "example.com"),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
                ("host", "example.com"),
            ],
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

        headers = [
            HeaderTuple(":authority", "example.com"),
            HeaderTuple(":path", "/"),
            HeaderTuple(":scheme", "https"),
            HeaderTuple(":method", "POST"),
        ]

        # Tempesta must not save large header in dynamic table.
        client.send_request(request=headers, expected_status_code="200")

        # Client received large header as plain text.
        client.send_request(request=headers, expected_status_code="200")
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

    def test_updating_dynamic_table(self):
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

    def test_clearing_dynamic_table(self):
        """
        "an attempt to add an entry larger than the maximum size causes the table
        to be emptied of all existing entries and results in an empty table."
        RFC 7541 4.4
        """
        self.start_all_services()
        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")
        client.parsing = False

        headers = [
            HeaderTuple(":authority", "example.com"),
            HeaderTuple(":path", "/"),
            HeaderTuple(":scheme", "https"),
            HeaderTuple(":method", "GET"),
        ]
        client.send_request(
            # Tempesta save header with 1k bytes in dynamic table.
            request=(headers + [HeaderTuple("a", "a" * 1000)]),
            expected_status_code="200",
        )

        client.send_request(
            # Tempesta MUST clear dynamic table
            # because new indexed header is larger than 4096 bytes
            request=(headers + [HeaderTuple("a", "a" * 6000)]),
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

        headers = [
            HeaderTuple(":authority", "example.com"),
            HeaderTuple(":path", "/"),
            HeaderTuple(":scheme", "https"),
            HeaderTuple(":method", "POST"),
        ]

        # Tempesta forwards response with via header and saves it in dynamic table.
        client.send_request(request=headers, expected_status_code="200")
        self.assertIn(b"2.0 tempesta_fw (Tempesta FW pre-0.7.0)", client.response_buffer)

        # Tempesta forwards header from dynamic table. Via header is indexed.
        client.send_request(request=headers, expected_status_code="200")
        self.assertNotIn(b"2.0 tempesta_fw (Tempesta FW pre-0.7.0)", client.response_buffer)

        # Tempesta MUST clear dynamic table when receive SETTINGS_HEADER_TABLE_SIZE = 0
        client.send_settings_frame(header_table_size=0)
        self.assertTrue(client.wait_for_ack_settings())

        client.send_settings_frame(header_table_size=4096)
        self.assertTrue(client.wait_for_ack_settings())

        # Tempesta MUST saves via header in dynamic table again. Via header is indexed again.
        client.send_request(request=headers, expected_status_code="200")
        self.assertIn(b"2.0 tempesta_fw (Tempesta FW pre-0.7.0)", client.response_buffer)

        # Tempesta forwards header from dynamic table again.
        client.send_request(request=headers, expected_status_code="200")
        self.assertNotIn(b"2.0 tempesta_fw (Tempesta FW pre-0.7.0)", client.response_buffer)

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
                    request=[
                        HeaderTuple(":authority", "example.com"),
                        HeaderTuple(":path", "/"),
                        HeaderTuple(":scheme", "https"),
                        HeaderTuple(":method", "POST"),
                        HeaderTuple(b"a", b"a" * 4063),
                    ],
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
