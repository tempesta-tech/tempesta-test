"""Functional tests for stream states."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from hyperframe.frame import (
    DataFrame,
    Frame,
    PriorityFrame,
    RstStreamFrame,
    WindowUpdateFrame,
)

from http2_general.helpers import H2Base


class TestClosedStreamState(H2Base, no_reload=True):
    def __base_scenario(self, frame: Frame):
        """
        An endpoint that sends a frame with the END_STREAM flag set or a RST_STREAM frame might
        receive a WINDOW_UPDATE or RST_STREAM frame from its peer in the time before the peer
        receives and processes the frame that closes the stream.
        RFC 9113 5.1

        Tempesta MUST not close connection.
        """
        self.start_all_services()

        client = self.get_client("deproxy")
        client.send_request(request=self.post_request, expected_status_code="200")
        client.send_bytes(frame.serialize())
        client.send_request(request=self.post_request, expected_status_code="200")

    def test_rst_stream_frame_in_closed_state(self):
        self.__base_scenario(RstStreamFrame(stream_id=1))

    def test_window_update_frame_in_closed_state(self):
        self.__base_scenario(WindowUpdateFrame(stream_id=1))

    def test_priority_frame_in_closed_state(self):
        """
        An endpoint MUST NOT send frames other than PRIORITY on a closed stream.
        RFC 9113 5.1

        Tempesta MUST not close connection.
        """
        self.__base_scenario(PriorityFrame(stream_id=1))


class TestHalfClosedStreamStateUnexpectedFrames(H2Base, no_reload=True):
    def __base_scenario(self, frame: Frame):
        """
        If an endpoint receives additional frames, other than WINDOW_UPDATE, PRIORITY,
        or RST_STREAM, for a stream that is in this state, it MUST respond with a stream
        error (Section 5.4.2) of type STREAM_CLOSED.
        RFC 9113 5.1

        Tempesta MUST not close connection.
        """
        client = self.get_client("deproxy")
        client.encoder.huffman = True

        self.start_all_services()
        self.initiate_h2_connection(client)

        client.h2_connection.send_headers(stream_id=1, headers=self.get_request, end_stream=True)
        client.send_bytes(
            data=(
                client.h2_connection.data_to_send()
                + DataFrame(stream_id=1, data=b"request body").serialize()
                + frame.serialize()
            ),
            expect_response=True,
        )

        # TODO Uncomment by issue #1819
        # self.assertTrue(client.wait_for_response(3))
        # self.assertEqual(client.last_response.status, '400')
        self.assertTrue(client.wait_for_reset_stream(stream_id=1))

        client.stream_id += 2
        client.send_request(self.get_request, "200")

    def test_priority_frame_in_half_closed_state(self):
        self.__base_scenario(frame=PriorityFrame(stream_id=1))

    def test_reset_frame_in_half_closed_state(self):
        self.__base_scenario(frame=RstStreamFrame(stream_id=1))

    def test_window_update_frame_in_half_closed_state(self):
        self.__base_scenario(frame=WindowUpdateFrame(stream_id=1))


class TestHalfClosedStreamStateWindowUpdate(H2Base):
    def test_window_update_frame_in_half_closed_state(self):
        """
        An endpoint should receive and accept WINDOW_UPDATE frame
        on half-closed (remote) stream.

        Tempesta must accept WINDOW_UPDATE frame on half-closed
        (remote) stream and continue to send pending data.
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

        client.update_initial_settings(initial_window_size=0)
        client.send_bytes(client.h2_connection.data_to_send())
        client.wait_for_ack_settings()

        client.make_request(self.post_request)
        self.assertFalse(client.wait_for_response(2))

        client.h2_connection.increment_flow_control_window(2000)
        client.h2_connection.increment_flow_control_window(2000, stream_id=1)
        client.send_bytes(client.h2_connection.data_to_send())
        client.h2_connection.clear_outbound_data_buffer()

        self.assertTrue(client.wait_for_response(2))
        self.assertEqual(client.last_response.status, "200")
        self.assertEqual(
            len(client.last_response.body), 2000, "Tempesta did not return full response body."
        )
