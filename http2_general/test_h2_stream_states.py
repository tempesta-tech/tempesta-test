"""Functional tests for stream states."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from hyperframe.frame import PriorityFrame, RstStreamFrame, WindowUpdateFrame

from http2_general.helpers import H2Base


class TestClosedStreamState(H2Base):
    def test_rst_stream_frame_in_closed_state(self):
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
        client.send_bytes(RstStreamFrame(stream_id=1).serialize())
        client.send_request(request=self.post_request, expected_status_code="200")

    def test_window_update_frame_in_closed_state(self):
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
        client.send_bytes(WindowUpdateFrame(stream_id=1).serialize())
        client.send_request(request=self.post_request, expected_status_code="200")

    def test_priority_frame_in_closed_state(self):
        """
        An endpoint MUST NOT send frames other than PRIORITY on a closed stream.
        RFC 9113 5.1

        Tempesta MUST not close connection.
        """
        self.start_all_services()

        client = self.get_client("deproxy")
        client.send_request(request=self.post_request, expected_status_code="200")
        client.send_bytes(PriorityFrame(stream_id=1).serialize())
        client.send_request(request=self.post_request, expected_status_code="200")
