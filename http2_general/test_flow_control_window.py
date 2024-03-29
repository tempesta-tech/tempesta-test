"""Functional tests for flow control window."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from h2.exceptions import FlowControlError

from helpers.deproxy import HttpMessage
from http2_general.helpers import H2Base


class TestFlowControl(H2Base):
    def test_flow_control_window_for_stream(self):
        """
        Client sets SETTINGS_INITIAL_WINDOW_SIZE = 1k bytes and backend returns response
        with 2k bytes body.
        Tempesta must forward DATA frame with 1k bytes and wait WindowUpdate from client.
        """
        self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + "Server: debian\r\n"
            + "Content-Length: 2000\r\n\r\n"
            + ("x" * 2000)
        )

        client.update_initial_settings(initial_window_size=1000)
        client.send_bytes(client.h2_connection.data_to_send())
        client.wait_for_ack_settings()

        client.make_request(self.post_request)
        client.wait_for_response(3)

        self.assertNotIn(
            FlowControlError, client.error_codes, "Tempesta ignored flow control window for stream."
        )
        self.assertFalse(client.connection_is_closed())
        self.assertEqual(client.last_response.status, "200", "Status code mismatch.")
        self.assertEqual(
            len(client.last_response.body), 2000, "Tempesta did not return full response body."
        )

    def test_request_body_greater_than_initial_window_size(self):
        self.start_all_services()

        server = self.get_server("deproxy")
        server.set_response(
            response=(
                "HTTP/1.1 200 OK\r\n"
                + f"Date: {HttpMessage.date_time_string()}\r\n"
                + "Server: debian\r\n"
                + "Content-Length: 0\r\n\r\n"
            )
        )

        client = self.get_client("deproxy")

        client.update_initial_settings()
        client.send_bytes(client.h2_connection.data_to_send())
        client.wait_for_ack_settings()

        expected_window_size = 65535
        window_size_from_tempesta = client.h2_connection.remote_settings.initial_window_size
        self.assertEqual(
            window_size_from_tempesta,
            expected_window_size,
            f"Tempesta set INITIAL_WINDOW_SIZE: {window_size_from_tempesta}. "
            f"But expected: {expected_window_size}.",
        )

        request = client.create_request(
            method="POST", headers=[], body="a" * (expected_window_size * 2)
        )
        client.send_request(request, "200")
