"""Functional tests for flow control window."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from h2.exceptions import FlowControlError

from http2_general.helpers import H2Base


class TestFlowControl(H2Base):
    def test_flow_control_window_with_long_headers(self):
        """
        Chnaging of SETTINGS_INITIAL_WINDOW_SIZE doesn't affect
        forwarding of HEADERS frames.
        """
        client, server = self.__setup_settings_header_table_tests(1000)

        large_header = ("qwerty", "x" * 100000)
        server.set_response(
            "HTTP/1.1 200 OK\r\n" + "Date: test\r\n" + "Server: debian\r\n"
            f"{large_header[0]}: {large_header[1]}\r\n" + "Content-Length: 0\r\n\r\n"
        )

        client.make_request(self.post_request)
        client.wait_for_response(3)

        self.assertNotIn(
            FlowControlError, client.error_codes, "Tempesta ignored flow control window for stream."
        )
        self.assertFalse(client.connection_is_closed())
        self.assertEqual(client.last_response.status, "200", "Status code mismatch.")
        self.assertIsNotNone(client.last_response.headers.get(large_header[0]))
        self.assertEqual(
            len(client.last_response.headers.get(large_header[0])), len(large_header[1])
        )

    def test_flow_control_window_with_long_body(self):
        """ """
        client, server = self.__setup_settings_header_table_tests(65535)
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Date: test\r\n"
            + "Server: debian\r\n"
            + "Content-Length: 65535\r\n\r\n"
            + ("x" * 65535)
        )

        client.make_request(self.post_request)
        client.wait_for_response(3)

        self.assertNotIn(
            FlowControlError, client.error_codes, "Tempesta ignored flow control window for stream."
        )
        self.assertFalse(client.connection_is_closed())
        self.assertEqual(client.last_response.status, "200", "Status code mismatch.")
        self.assertEqual(
            len(client.last_response.body), 65535, "Tempesta did not return full response body."
        )

    def test_flow_control_window_with_long_body_and_headers(self):
        """ """
        client, server = self.__setup_settings_header_table_tests(65535)

        large_header = ("qwerty", "x" * 100000)
        server.set_response(
            "HTTP/1.1 200 OK\r\n" + "Date: test\r\n" + "Server: debian\r\n"
            f"{large_header[0]}: {large_header[1]}\r\n"
            + "Content-Length: 65535\r\n\r\n"
            + ("x" * 65535)
        )

        client.make_request(self.post_request)
        client.wait_for_response(3)

        self.assertNotIn(
            FlowControlError, client.error_codes, "Tempesta ignored flow control window for stream."
        )
        self.assertFalse(client.connection_is_closed())
        self.assertEqual(client.last_response.status, "200", "Status code mismatch.")
        self.assertIsNotNone(client.last_response.headers.get(large_header[0]))
        self.assertEqual(
            len(client.last_response.headers.get(large_header[0])), len(large_header[1])
        )
        self.assertEqual(
            len(client.last_response.body), 65535, "Tempesta did not return full response body."
        )

    def test_flow_control_window_for_stream(self):
        """
        Client sets SETTINGS_INITIAL_WINDOW_SIZE = 1k bytes and backend returns response
        with 2k bytes body.
        Tempesta must forward DATA frame with 1k bytes and wait WindowUpdate from client.
        """
        client, server = self.__setup_settings_header_table_tests(1000)
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Date: test\r\n"
            + "Server: debian\r\n"
            + "Content-Length: 2000\r\n\r\n"
            + ("x" * 2000)
        )

        client.make_request(self.post_request)
        client.wait_for_response(3)

        self.assertNotIn(
            FlowControlError, client.error_codes, "Tempesta ignored flow control window for stream."
        )
        print(client.last_response)
        self.assertFalse(client.connection_is_closed())
        self.assertEqual(client.last_response.status, "200", "Status code mismatch.")
        self.assertEqual(
            len(client.last_response.body), 2000, "Tempesta did not return full response body."
        )

    def __setup_settings_header_table_tests(self, initial_window_size):
        self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        client.update_initial_settings(initial_window_size=initial_window_size)
        client.send_bytes(client.h2_connection.data_to_send())
        client.wait_for_ack_settings()

        return client, server
