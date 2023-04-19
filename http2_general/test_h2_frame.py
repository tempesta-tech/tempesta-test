"""Functional tests for h2 frames."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from h2.errors import ErrorCodes
from h2.exceptions import StreamClosedError

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
        client.update_initial_settings()

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

        client.update_initial_settings()
        client.send_bytes(client.h2_connection.data_to_send())
        client.h2_connection.clear_outbound_data_buffer()

        # H2Connection separates headers to HEADERS + CONTINUATION frames
        # if they are larger than 16384 bytes
        client.send_request(
            request=self.get_request + [("qwerty", "x" * 5000) for _ in range(4)],
            expected_status_code="200",
        )

        self.assertFalse(client.connection_is_closed())

    def test_rst_frame_in_request(self):
        """
        Tempesta must handle RST_STREAM frame and close stream but other streams MUST work.
        """
        client = self.get_client("deproxy")

        self.start_all_services()
        self.initiate_h2_connection(client)

        # client opens streams with id 1, 3 and does not close them
        client.make_request(request=self.post_request, end_stream=False)
        client.stream_id = 3
        client.make_request(request=self.post_request, end_stream=False)

        # client send RST_STREAM frame with NO_ERROR code in stream 1 and
        # Tempesta closes it for itself.
        client.h2_connection.reset_stream(stream_id=1, error_code=0)
        client.send_bytes(client.h2_connection.data_to_send())

        # Client send DATA frame in stream 3 and it MUST receive response
        client.send_request("qwe", "200")

        # Tempesta allows creating new streams.
        client.stream_id = 5
        client.send_request(self.post_request, "200")

        self.assertFalse(
            client.connection_is_closed(), "Tempesta closed connection after receiving RST_STREAM."
        )

    def test_rst_frame_in_response(self):
        """
        When Tempesta returns RST_STREAM:
         - open streams must not be closed;
         - new streams must be accepted.
        """
        client = self.get_client("deproxy")
        client.parsing = False

        self.start_all_services()
        self.initiate_h2_connection(client)

        # client opens stream with id 1 and does not close it
        client.make_request(request=self.post_request, end_stream=False)

        # client send invalid request and Tempesta returns RST_STREAM
        stream_with_rst = 3
        client.stream_id = stream_with_rst
        client.send_request((self.get_request + [("host", "")], "asd"), "400")

        # client open new stream
        client.make_request(self.get_request, end_stream=True)
        client.wait_for_response(3)

        # client send DATA frame in stream 1 and it must be open.
        client.stream_id = 1
        client.make_request("body", end_stream=True)
        client.wait_for_response(3)

        self.assertRaises(
            StreamClosedError, client.h2_connection._get_stream_by_id, stream_with_rst
        )
        self.assertFalse(
            client.connection_is_closed(), "Tempesta closed connection after sending RST_STREAM."
        )

    def test_rst_stream_with_id_0(self):
        """
        RST_STREAM frames MUST be associated with a stream. If a RST_STREAM frame
        is received with a stream identifier of 0x00, the recipient MUST treat this
        as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.
        RFC 9113 6.4
        """
        client = self.get_client("deproxy")

        self.start_all_services()
        self.initiate_h2_connection(client)

        # send RST_STREAM with id 0
        client.send_bytes(b"\x00\x00\x04\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00")

        self.assertTrue(
            client.wait_for_connection_close(1),
            "Tempesta did not close connection after receiving RST_STREAM with id 0.",
        )
        self.assertIn(ErrorCodes.PROTOCOL_ERROR, client.error_codes)

    def test_goaway_frame_in_response(self):
        """
        Tempesta must:
         - close all streams for connection error (GOAWAY);
         - return last_stream_id.

        There is an inherent race condition between an endpoint starting new streams
        and the remote peer sending a GOAWAY frame. To deal with this case, the GOAWAY
        contains the stream identifier of the last peer-initiated stream that was or
        might be processed on the sending endpoint in this connection. For instance,
        if the server sends a GOAWAY frame, the identified stream is the highest-numbered
        stream initiated by the client.
        RFC 9113 6.8
        """
        client = self.get_client("deproxy")

        self.start_all_services()
        self.initiate_h2_connection(client)

        # Client opens many streams and does not close them
        for stream_id in range(1, 6, 2):
            client.stream_id = stream_id
            client.make_request(request=self.post_request, end_stream=False)

        # Client send DATA frame with stream id 0.
        # Tempesta MUST return GOAWAY frame with PROTOCOL_ERROR
        client.send_bytes(b"\x00\x00\x03\x00\x01\x00\x00\x00\x00asd")

        self.assertTrue(client.wait_for_connection_close(3), "Tempesta did not send GOAWAY frame.")
        self.assertIn(ErrorCodes.PROTOCOL_ERROR, client.error_codes)
        self.assertEqual(
            client.last_stream_id,
            stream_id,
            "Tempesta returned invalid last_stream_id in GOAWAY frame.",
        )

    def test_goaway_frame_in_request(self):
        """
        Tempesta must not close connection after receiving GOAWAY frame.

        GOAWAY allows an endpoint to gracefully stop accepting new streams while still
        finishing processing of previously established streams.
        RFC 9113 6.8
        """
        client = self.get_client("deproxy")

        self.start_all_services()
        self.initiate_h2_connection(client)

        # Client opens many streams and does not close them
        for stream_id in range(1, 6, 2):
            client.stream_id = stream_id
            client.make_request(request=self.post_request, end_stream=False)

        # Client send GOAWAY frame with PROTOCOL_ERROR as bytes
        # because `_terminate_connection` method changes state machine to closed
        client.send_bytes(b"\x00\x00\x08\x07\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x01")

        # Client sends frames in already open streams.
        # Tempesta must handle these frames and must not close streams,
        # because sender closes connection, but not receiver.
        for stream_id in range(1, 6, 2):
            client.stream_id = stream_id
            client.make_request(request="asd", end_stream=True)

        self.assertTrue(
            client.wait_for_response(), "Tempesta closed connection after receiving GOAWAY frame."
        )

    def test_double_header_frame_in_single_stream(self):
        client = self.get_client("deproxy")

        self.start_all_services()
        self.initiate_h2_connection(client)

        client.make_request(self.post_request, end_stream=False)
        client.make_request([("header1", "header value1")], end_stream=True)

        self.assertTrue(client.wait_for_connection_close())
        self.assertIn(ErrorCodes.PROTOCOL_ERROR, client.error_codes)

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
