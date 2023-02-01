"""Functional tests for h2 frames."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import deproxy_client
from helpers import checks_for_tests as checks
from http2_general.helpers import H2Base


class TestH2Frame(H2Base):
    def test_data_framing(self):
        """Send many 1 byte frames in request."""
        self.start_all_services()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.parsing = False
        request_body = "x" * 100

        deproxy_cl.make_request(request=self.post_request, end_stream=False)
        for byte in request_body[:-1]:
            deproxy_cl.make_request(request=byte, end_stream=False)
        deproxy_cl.make_request(request=request_body[-1], end_stream=True)

        self.__assert_test(client=deproxy_cl, request_body=request_body, request_number=1)

    def test_empty_last_data_frame(self):
        """
        Send request with empty last data frame. It is valid request. RFC 9113 6.9.1.
        """
        self.start_all_services()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.parsing = False
        request_body = "123"

        deproxy_cl.make_request(request=self.post_request, end_stream=False)
        deproxy_cl.make_request(request=request_body, end_stream=False)
        deproxy_cl.make_request(request="", end_stream=True)

        self.__assert_test(client=deproxy_cl, request_body=request_body, request_number=1)

    def test_empty_data_frame(self):
        """
        Send request with empty data frame. It is valid request. RFC 9113 10.5.
        """
        self.start_all_services()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.parsing = False
        request_body = "123"

        deproxy_cl.make_request(request=self.post_request, end_stream=False)
        deproxy_cl.make_request(request="", end_stream=False)
        deproxy_cl.make_request(request=request_body, end_stream=True)

        self.__assert_test(client=deproxy_cl, request_body=request_body, request_number=1)

    def test_tcp_framing_for_request_headers(self):
        """Client sends PRI+SETTING+HEADERS frames by 1-byte chunks."""
        client = self.get_client("deproxy")
        client.segment_size = 1
        self.start_all_services()
        client.parsing = False

        client.make_request(self.post_request)

        self.__assert_test(client=client, request_body="", request_number=1)

    def test_tcp_framing_for_request(self):
        """Client sends request by n-byte chunks."""
        client = self.get_client("deproxy")
        self.start_all_services()
        client.parsing = False

        chunk_sizes = [1, 2, 3, 4, 8, 16]
        for chunk_size in chunk_sizes:
            with self.subTest(chunk_size=chunk_size):
                client.segment_size = chunk_size
                client.make_request(self.post_request, False)

                request_body = "0123456789"
                client.make_request(request_body, True)

                self.__assert_test(
                    client=client,
                    request_body=request_body,
                    request_number=chunk_sizes.index(chunk_size) + 1,
                )

    def test_settings_frame(self):
        """
        Create tls connection and send preamble + correct settings frame.
        Tempesta must accept settings and return settings + ack settings frames.
        Then client send ack settings frame and Tempesta must correctly accept it.
        """
        self.start_all_services(client=True)

        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")

        # initiate_connection() generates preamble + settings frame with default variables
        self.initiate_h2_connection(client)

        # send empty setting frame with ack flag.
        client.send_bytes(client.h2_connection.data_to_send())
        client.h2_connection.clear_outbound_data_buffer()

        # send header frame after exchanging settings and make sure
        # that connection is open.
        client.send_request(self.post_request, "200")

    def test_window_update_frame(self):
        """Tempesta must handle WindowUpdate frame."""
        self.start_all_services(client=True)

        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")

        # add preamble + settings frame with SETTING_INITIAL_WINDOW_SIZE = 65535
        client.update_initiate_settings()

        # send preamble + settings frame
        client.send_bytes(client.h2_connection.data_to_send())
        client.h2_connection.clear_outbound_data_buffer()
        self.assertTrue(client.wait_for_ack_settings())

        # send WindowUpdate frame with window size increment = 5000
        client.h2_connection.increment_flow_control_window(5000)
        client.send_bytes(client.h2_connection.data_to_send())
        client.h2_connection.clear_outbound_data_buffer()

        # send header frame after sending WindowUpdate and make sure
        # that connection is working correctly.
        client.send_request(self.get_request, "200")
        self.assertFalse(client.connection_is_closed())

    def test_continuation_frame(self):
        """Tempesta must handle CONTINUATION frame."""
        self.start_all_services()

        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")

        client.update_initiate_settings()
        client.send_bytes(client.h2_connection.data_to_send())
        client.h2_connection.clear_outbound_data_buffer()

        # H2Connection separates headers to HEADERS + CONTINUATION frames
        # if they are larger than 16384 bytes
        client.send_request(
            request=self.get_request + [("qwerty", "x" * 5000) for _ in range(4)],
            expected_status_code="200",
        )

        self.assertFalse(client.connection_is_closed())

    def __assert_test(self, client, request_body: str, request_number: int):
        server = self.get_server("deproxy")

        self.assertTrue(client.wait_for_response(timeout=5))
        self.assertEqual(client.last_response.status, "200")
        self.assertEqual(len(server.requests), request_number)
        checks.check_tempesta_request_and_response_stats(
            tempesta=self.get_tempesta(),
            cl_msg_received=request_number,
            cl_msg_forwarded=request_number,
            srv_msg_received=request_number,
            srv_msg_forwarded=request_number,
        )
        error_msg = "Malformed request from Tempesta."
        self.assertEqual(server.last_request.method, self.post_request[3][1], error_msg)
        self.assertEqual(server.last_request.headers["host"], self.post_request[0][1], error_msg)
        self.assertEqual(server.last_request.uri, self.post_request[1][1], error_msg)
        self.assertEqual(server.last_request.body, request_body)
