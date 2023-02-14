"""Functional tests for flow control window."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from h2.exceptions import FlowControlError

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
            + "Date: test\r\n"
            + "Server: debian\r\n"
            + "Content-Length: 2000\r\n\r\n"
            + ("x" * 2000)
        )

        client.update_initial_settings(initial_window_size=1000)
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
