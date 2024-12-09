"""
Tests for TCP connection
"""

from typing import Optional

from scapy.layers.inet import TCP
from scapy.packet import Raw

from helpers.tcp_client import (
    ScapyLocalhostRequestFix,
    ScapyTCPHandshakeResetFix,
    SimpleTCPClient,
)
from test_suite import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TesTCPConnection(tester.TempestaTest):
    tempesta = {
        "config": """
            cache 0;
            listen 80;
            server ${server_ip}:8000;
        """
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.tcp_client: Optional[SimpleTCPClient] = None

    def setUp(self):
        super().setUp()

        self.start_tempesta()
        self.start_all_servers()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections())

        tempest_host = self.get_tempesta()
        self.tcp_client = SimpleTCPClient(
            destination_host=tempest_host.host,
            destination_port=80,
            timeout=1,
        )
        self.tcp_client.fixes_install(ScapyTCPHandshakeResetFix, ScapyLocalhostRequestFix)

    def tearDown(self):
        super().tearDown()
        self.tcp_client.fixes_rollback()

    def test_tcp_connection_open_and_close_successfully(self):
        """
        Open and close tcp connection
        """
        init_request, init_response = self.tcp_client.request(flags="S")
        self.assertIsNotNone(init_response)
        self.assertEqual(init_response[TCP].flags, "SA")

        _, response = self.tcp_client.request(
            flags="A", seq=init_request[TCP].seq + 1, ack=init_response[TCP].seq + 1
        )
        self.assertIsNone(response)

        _, response = self.tcp_client.request(
            flags="FA", seq=init_request[TCP].seq + 1, ack=init_response[TCP].seq + 1
        )
        self.assertIsNotNone(response)
        self.assertEqual(response[TCP].flags, "FA")

        _, response = self.tcp_client.request(
            flags="FA", seq=init_request[TCP].seq + 2, ack=init_response[TCP].seq + 2
        )
        self.assertIsNone(response)

    def test_tcp_connection_reset_by_bad_request(self):
        """
        Trigger bad request and force server to close connection
        """
        init_request, init_response = self.tcp_client.request(flags="S")
        self.assertIsNotNone(init_response)
        self.assertEqual(init_response[TCP].flags, "SA")

        _, response = self.tcp_client.request(
            flags="A", seq=init_request[TCP].seq + 1, ack=init_response[TCP].seq + 1
        )
        self.assertIsNone(response)

        tempest = self.get_tempesta()
        message = b"GET / HxTP/1.1\r\nHost: " + tempest.host.encode() + b"\r\n\r\n"

        _, response = self.tcp_client.request_last_answer(
            flags="PA", seq=init_request[TCP].seq + 1, ack=init_response[TCP].seq + 1, data=message
        )
        self.assertIsNotNone(response)
        self.assertEqual(response[TCP].flags, "FA")

        message_parts = response[TCP][Raw].load.decode().split("\r\n")
        self.assertEqual(message_parts[0], "HTTP/1.1 400 Bad Request")
        self.assertTrue(message_parts[1].startswith("date:"))
        self.assertEqual(message_parts[2], "content-length: 0")
        self.assertTrue(message_parts[3].startswith("server: Tempesta FW/"))
        self.assertEqual(message_parts[4], "connection: close")

        _, response = self.tcp_client.request(
            flags="FA",
            seq=init_request[TCP].seq + 2 + len(message),
            ack=init_response[TCP].seq + 1 + len(response[TCP][Raw]),
        )
        self.assertIsNotNone(response)
        self.assertEqual(response[TCP].flags, "R")

    def test_tcp_connection_success_communications(self):
        """
        Test sending valid payload
        """
        init_request, init_response = self.tcp_client.request(flags="S")
        self.assertIsNotNone(init_response)
        self.assertEqual(init_response[TCP].flags, "SA")

        _, response = self.tcp_client.request(
            flags="A", seq=init_request[TCP].seq + 1, ack=init_response[TCP].seq + 1
        )
        self.assertIsNone(response)

        tempest = self.get_tempesta()
        message = b"GET / HTTP/1.1\r\nHost: " + tempest.host.encode() + b"\r\n\r\n"

        _, response = self.tcp_client.request_last_answer(
            flags="PA", seq=init_request[TCP].seq + 1, ack=init_response[TCP].seq + 1, data=message
        )
        self.assertIsNotNone(response)
        self.assertEqual(response[TCP].flags, "PA")

        response_message_len = len(response[TCP][Raw])
        message_parts = response[TCP][Raw].load.decode().split("\r\n")

        self.assertEqual(message_parts[0], "HTTP/1.1 502 Bad Gateway")
        self.assertTrue(message_parts[1].startswith("date:"))
        self.assertEqual(message_parts[2], "content-length: 0")
        self.assertTrue(message_parts[3].startswith("server: Tempesta FW/"))

        _, response = self.tcp_client.request(
            flags="A",
            seq=init_request[TCP].seq + 1 + len(message) + 1,
            ack=init_response[TCP].seq + 1 + response_message_len,
        )
        self.assertIsNone(response)

        _, response = self.tcp_client.request(
            flags="FA",
            seq=init_request[TCP].seq + 1 + len(message),
            ack=init_response[TCP].seq + 1 + response_message_len,
        )
        self.assertIsNotNone(response)
        self.assertEqual(response[TCP].flags, "FA")

        _, response = self.tcp_client.request(
            flags="A",
            seq=init_request[TCP].seq + 1 + len(message) + 1,
            ack=init_response[TCP].seq + 1 + response_message_len + 1,
        )
        self.assertIsNone(response)
