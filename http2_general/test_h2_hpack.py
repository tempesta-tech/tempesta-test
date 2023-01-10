"""Functional tests for HPACK."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

import time
from ssl import SSLWantWriteError

from h2.exceptions import ProtocolError
from hpack import HeaderTuple, NeverIndexedHeaderTuple
from hyperframe.frame import HeadersFrame

from framework import deproxy_client, tester


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
