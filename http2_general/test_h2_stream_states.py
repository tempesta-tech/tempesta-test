"""Functional tests for stream states."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from h2.connection import ConnectionInputs
from h2.errors import ErrorCodes
from h2.stream import StreamInputs
from hyperframe.frame import (
    ContinuationFrame,
    DataFrame,
    Frame,
    HeadersFrame,
    PriorityFrame,
    HeadersFrame,
    RstStreamFrame,
    WindowUpdateFrame,
)

from framework.parameterize import param, parameterize, parameterize_class
from helpers import dmesg
from helpers.deproxy import HttpMessage
from http2_general.helpers import H2Base
from h2.errors import ErrorCodes


class TestClosedStreamState(H2Base):
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
        self.__base_scenario(WindowUpdateFrame(stream_id=1, window_increment=1))

    def test_priority_frame_in_closed_state(self):
        """
        An endpoint MUST NOT send frames other than PRIORITY on a closed stream.
        RFC 9113 5.1

        Tempesta MUST not close connection.
        """
        self.__base_scenario(PriorityFrame(stream_id=1))


class TestLocHalfClosedStreamState(H2Base):

    PARSER_WARN = "HTTP/2 request dropped"

    def test_headers(self):
        """
        Send HEADERS frame to stream in LOC_CLOSED(internal Tempesta's state) state.
        The frame must be ignored by parser.
        """
        klog = dmesg.DmesgFinder(disable_ratelimit=True)
        client = self.get_client("deproxy")

        self.start_all_services()
        self.initiate_h2_connection(client)

        stream = client.init_stream_for_send(client.stream_id)
        client.h2_connection.state_machine.process_input(ConnectionInputs.SEND_HEADERS)

        hf = HeadersFrame(
            stream_id=stream.stream_id,
            data=client.h2_connection.encoder.encode(self.get_request),
            flags=["END_HEADERS"],
        )
        # Send first HEADERS to create stream.
        client.send_bytes(
            hf.serialize(),
            expect_response=False,
        )

        hf2 = HeadersFrame(
            stream_id=stream.stream_id,
            data=client.h2_connection.encoder.encode([("abc", "z<>")]),
            flags=["END_HEADERS", "END_STREAM"],
        )

        prio = PriorityFrame(stream_id=stream.stream_id, depends_on=stream.stream_id)
        # Send invalid PRIORITY frame to close the stream, after send invalid HEADERS frame.
        # If HEADERS frame will be passed to parser error message will be printed to log.
        client.send_bytes(
            prio.serialize() + hf2.serialize(),
            expect_response=True,
        )

        self.assertTrue(client.wait_for_reset_stream(stream_id=stream.stream_id))
        # If error message found test fails.
        self.assertFalse(
            klog.find(self.PARSER_WARN), "Frame is passed to parser in a CLOSED state."
        )


class TestHalfClosedStreamStateUnexpectedFrames(H2Base):
    def __base_scenario(self, frame: Frame):
        """
        If an endpoint receives additional frames, other than WINDOW_UPDATE, PRIORITY,
        or RST_STREAM, for a stream that is in this state, it MUST respond with a stream
        error (Section 5.4.2) of type STREAM_CLOSED.
        RFC 9113 5.1

        Tempesta MUST not close connection.
        """
        client = self.get_client("deproxy")

        self.start_all_services()
        self.initiate_h2_connection(client)
        client.h2_connection.encoder.huffman = True

        client.h2_connection.send_headers(stream_id=1, headers=self.get_request, end_stream=True)
        client.send_bytes(
            data=(
                client.h2_connection.data_to_send()
                + DataFrame(stream_id=1, data=b"request body").serialize()
                + frame.serialize()
            ),
            expect_response=False,
        )

        # When Tempesta receive RST STREAM frame, it immediately
        # close and delete stream
        if not isinstance(frame, RstStreamFrame):
            self.assertTrue(client.wait_for_reset_stream(stream_id=1))

        client.stream_id += 2
        client.send_request(self.get_request, "200")

    def test_priority_frame_in_half_closed_state(self):
        self.__base_scenario(frame=PriorityFrame(stream_id=1))

    def test_reset_frame_in_half_closed_state(self):
        self.__base_scenario(frame=RstStreamFrame(stream_id=1))

    def test_window_update_frame_in_half_closed_state(self):
        self.__base_scenario(frame=WindowUpdateFrame(stream_id=1, window_increment=1))


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
            + f"Date: {HttpMessage.date_time_string()}\r\n"
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


@parameterize_class(
    [
        {"name": "Cont", "flags": []},
        {"name": "ContClosed", "flags": ["END_STREAM"]},
    ]
)
class TestStreamState(H2Base):
    """
    There were two special states in tempesta for streams, which are not
    mentioned in the RFC. HTTP2_STREAM_CONT and HTTP2_STREAM_CONT_CLOSED.
    HTTP2_STREAM_CONT state is a state into which the stream goes after
    receiving headers without the END_HEADERS flag.
    HTTP2_STREAM_CONT_CLOSED is a state same as previos one, but if
    HTTP2_F_END_STREAM flag is received. (Currently we remove this states
    from tempesta code)
    """

    def __setup(self, request=None, expect_response=False):
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

        self.initiate_h2_connection(client)
        # create stream and change state machine in H2Connection object
        stream = client.init_stream_for_send(client.stream_id)

        request = request if request is not None else self.post_request
        hf = HeadersFrame(
            stream_id=client.stream_id,
            data=client.h2_connection.encoder.encode(request),
            flags=self.flags,
        )
        client.send_bytes(data=hf.serialize(), expect_response=expect_response)
        return client

    def test_any_frame_between_header_blocks(self):
        """
        Each field block is processed as a discrete unit. Field blocks MUST be
        transmitted as a contiguous sequence of frames, with no interleaved
        frames of any other type or from any other stream. The last frame in a
        sequence of HEADERS or CONTINUATION frames has the END_HEADERS flag set.
        The last frame in a sequence of PUSH_PROMISE or CONTINUATION frames has
        the END_HEADERS flag set. This allows a field block to be logically
        equivalent to a single frame.
        """
        client = self.__setup()
        hf = HeadersFrame(
            stream_id=client.stream_id,
            data=client.h2_connection.encoder.encode(self.post_request),
            flags=["END_HEADERS", "END_STREAM"],
        )
        client.send_bytes(data=hf.serialize(), expect_response=False)
        self.assertTrue(client.wait_for_connection_close())
        self.assertIn(ErrorCodes.PROTOCOL_ERROR, client.error_codes)

    def test_headers_frame_for_other_stream_between_header_blocks(self):
        """
        Each field block is processed as a discrete unit. Field blocks MUST be
        transmitted as a contiguous sequence of frames, with no interleaved
        frames of any other type or from any other stream. The last frame in a
        sequence of HEADERS or CONTINUATION frames has the END_HEADERS flag set.
        The last frame in a sequence of PUSH_PROMISE or CONTINUATION frames has
        the END_HEADERS flag set. This allows a field block to be logically
        equivalent to a single frame.
        """
        client = self.__setup()
        hf = HeadersFrame(
            stream_id=client.stream_id + 2,
            data=client.h2_connection.encoder.encode(self.post_request),
            flags=["END_HEADERS", "END_STREAM"],
        )
        client.send_bytes(data=hf.serialize(), expect_response=False)
        self.assertTrue(client.wait_for_connection_close())
        self.assertIn(ErrorCodes.PROTOCOL_ERROR, client.error_codes)

    def test_headers_frame_for_other_stream_after_rst(self):
        """
        If we reset stream, for which we are waiting END_HEADERS flag
        we can send headers for other streams.
        """
        client = self.__setup()
        hf = RstStreamFrame(stream_id=1)
        client.send_bytes(hf.serialize())
        client.stream_id = 3
        client.make_request(self.post_request)
        self.assertTrue(client.wait_for_response())
        self.assertEqual(client.last_response.status, "200")
        self.assertEqual(
            len(client.last_response.body), 2000, "Tempesta did not return full response body."
        )

    def test_error_request_between_header_blocks(self):
        """
        Test case when we don't receive END_HEADERS flag
        but have error during processing request.
        """
        client = self.__setup(self.post_request + [("BAD", "BAD")], True)
        self.assertTrue(client.wait_for_response())
        self.assertEqual(client.last_response.status, "400")


class TestTwoHeadersFramesFirstWithoutEndStream(H2Base):
    def test(self):
        self.disable_deproxy_auto_parser()
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

        self.initiate_h2_connection(client)
        # create stream and change state machine in H2Connection object
        stream = client.init_stream_for_send(client.stream_id)

        hf = HeadersFrame(
            stream_id=client.stream_id,
            data=client.h2_connection.encoder.encode(self.post_request),
            flags=["END_HEADERS"],
        )
        client.send_bytes(data=hf.serialize(), expect_response=False)

        client.stream_id = 3
        client.make_request(self.post_request)
        self.assertTrue(client.wait_for_response())
        self.assertEqual(client.last_response.status, "200")
        self.assertEqual(
            len(client.last_response.body), 2000, "Tempesta did not return full response body."
        )

        client.stream_id = 1
        client.make_request([("header", "x" * 320)])
        self.assertTrue(client.wait_for_response())
        self.assertEqual(client.last_response.status, "200")
        self.assertEqual(
            len(client.last_response.body), 2000, "Tempesta did not return full response body."
        )

        client.stream_id = 5
        client.make_request(self.post_request)
        self.assertTrue(client.wait_for_response())
        self.assertEqual(client.last_response.status, "200")
        self.assertEqual(
            len(client.last_response.body), 2000, "Tempesta did not return full response body."
        )


class TestIdleState(H2Base):
    def test_priority_frame_in_idle_state(self):
        """
        An endpoint should receive and accept PRIORITY frame
        on idle stream.
        """

        self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        client.update_initial_settings()
        client.send_bytes(client.h2_connection.data_to_send())
        client.wait_for_ack_settings()

        client.send_bytes(PriorityFrame(stream_id=3).serialize())
        client.stream_id = 3

        client.send_request(self.post_request, "200")

    def test_closing_idle_stream(self):
        """
        The first use of a new stream identifier implicitly closes all
        streams in the "idle" state that might have been initiated by
        that peer with a lower-valued stream identifier.
        """

        self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        client.update_initial_settings()
        client.send_bytes(client.h2_connection.data_to_send())
        client.wait_for_ack_settings()

        client.send_bytes(PriorityFrame(stream_id=7).serialize())
        client.stream_id = 11
        client.send_request(self.post_request, "200")

        """
        Idle stream with id == 7 should be moved to closed state
        during previous request. Headers frames are not allowed in
        the closed state. Connection is closed with PROTOCOL_ERROR
        """
        client.send_bytes(
            HeadersFrame(
                stream_id=7,
                data=client.h2_connection.encoder.encode(self.post_request),
                flags=["END_HEADERS"],
            ).serialize()
        )

        self.assertTrue(client.wait_for_connection_close())
        self.assertIn(ErrorCodes.PROTOCOL_ERROR, client.error_codes)

    def test_not_closing_idle_stream(self):
        """
        The first use of a new stream identifier implicitly closes all
        streams in the "idle" state that might have been initiated by
        that peer with a lower-valued stream identifier and not closes
        with a greater one.
        """

        self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        client.update_initial_settings()
        client.send_bytes(client.h2_connection.data_to_send())
        client.wait_for_ack_settings()

        client.send_bytes(PriorityFrame(stream_id=17).serialize())
        client.stream_id = 11
        client.send_request(self.post_request, "200")

        client.stream_id = 17
        client.send_request(self.post_request, "200")
