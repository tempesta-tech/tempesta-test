"""Functional tests for HPACK."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

from hpack import HeaderTuple, NeverIndexedHeaderTuple

from framework import tester


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
