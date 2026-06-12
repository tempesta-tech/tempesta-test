"""Functional tests for stream states."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

import asyncio
import socket
import typing

from h2.connection import ConnectionInputs
from h2.errors import ErrorCodes
from hyperframe.frame import (
    DataFrame,
    Frame,
    HeadersFrame,
    PriorityFrame,
    RstStreamFrame,
    WindowUpdateFrame,
)

from framework.deproxy.deproxy_message import HttpMessage
from framework.helpers import dmesg
from framework.test_suite import marks
from framework.test_suite.marks import parameterize_class
from tests.http2_general.helpers import H2Base


class TestClosedStreamState(H2Base):
    async def __base_scenario(self, send_frame_func: typing.Callable):
        """
        An endpoint that sends a frame with the END_STREAM flag set or a RST_STREAM frame might
        receive a WINDOW_UPDATE or RST_STREAM frame from its peer in the time before the peer
        receives and processes the frame that closes the stream.
        RFC 9113 5.1

        Tempesta MUST not close connection.
        """
        await self.start_all_services()

        client = self.get_client("deproxy")
        await client.send_request(request=self.post_request, expected_status_code="200")
        send_frame_func(client)
        await client.send_request(request=self.post_request, expected_status_code="200")

    async def test_rst_stream_frame_in_closed_state(self):
        await self.__base_scenario(lambda client: client.send_rst_stream_frame(stream_id=1))

    async def test_window_update_frame_in_closed_state(self):
        await self.__base_scenario(
            lambda client: client.send_window_update_frame(stream_id=1, window_increment=1)
        )

    async def test_priority_frame_in_closed_state(self):
        """
        An endpoint MUST NOT send frames other than PRIORITY on a closed stream.
        RFC 9113 5.1

        Tempesta MUST not close connection.
        """
        await self.__base_scenario(lambda client: client.send_priority_frame(stream_id=1))


class TestLocHalfClosedStreamState(H2Base):
    async def test_headers(self):
        """
        Send HEADERS frame to stream in LOC_CLOSED(internal Tempesta's state) state.
        The frame must be ignored by parser.
        """
        klog = dmesg.DmesgFinder(disable_ratelimit=True)
        client = self.get_client("deproxy")

        await self.start_all_services()
        await self.initiate_h2_connection(client)

        stream = client.init_stream_for_send(client.stream_id)
        client.h2_connection.state_machine.process_input(ConnectionInputs.SEND_HEADERS)

        # Send first HEADERS to create stream.
        client.send_headers_frame(
            stream_id=stream.stream_id,
            data=client.h2_connection.encoder.encode(self.get_request),
            flags=["END_HEADERS"],
            expect_response=False,
        )

        # Send invalid PRIORITY frame to close the stream, after send invalid HEADERS frame.
        # If HEADERS frame will be passed to parser error message will be printed to log.
        client.send_priority_frame(stream_id=stream.stream_id, depends_on=stream.stream_id)

        client.send_headers_frame(
            stream_id=stream.stream_id,
            data=client.h2_connection.encoder.encode([("abc", "z<>")]),
            flags=["END_HEADERS", "END_STREAM"],
            expect_response=True,
        )

        await client.wait_for_connection_close()
        self.assertIsNone(client.last_response)


class TestHalfClosedStreamStateUnexpectedFrames(H2Base):
    async def __base_scenario(self, frame: Frame):
        """
        If an endpoint receives additional frames, other than WINDOW_UPDATE, PRIORITY,
        or RST_STREAM, for a stream that is in this state, it MUST respond with a stream
        error (Section 5.4.2) of type STREAM_CLOSED.
        RFC 9113 5.1

        Tempesta MUST not close connection.
        """
        client = self.get_client("deproxy")

        await self.start_all_services()
        await self.initiate_h2_connection(client)
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
            await client.wait_for_reset_stream(stream_id=1)

        client.stream_id += 2
        client.make_request(self.get_request)
        await client.wait_for_response(n=1)
        self.assertEqual(client.last_response.status, "200")

    async def test_priority_frame_in_half_closed_state(self):
        await self.__base_scenario(frame=PriorityFrame(stream_id=1))

    async def test_reset_frame_in_half_closed_state(self):
        await self.__base_scenario(frame=RstStreamFrame(stream_id=1))

    async def test_window_update_frame_in_half_closed_state(self):
        await self.__base_scenario(frame=WindowUpdateFrame(stream_id=1, window_increment=1))

    def _get_srv_msg_forwarded_stat(self, tempesta):
        tempesta.get_stats()
        return tempesta.stats.srv_msg_forwarded

    def _send_headers_frame(self, client, stream_id):
        client.send_headers_frame(
            stream_id=stream_id,
            exclusive=False,
            data=client.h2_connection.encoder.encode(self.get_request),
            flags=["END_HEADERS", "END_STREAM"],
        )

    def _send_data_frame(self, client, stream_id):
        client.send_data_frame(stream_id=stream_id, data=b"a")

    def _send_rst_frame(self, client, stream_id):
        client.send_rst_stream_frame(stream_id=stream_id)

    def _check_all_headers_presents_in_partially_received_response(self, response):
        # Check all headers received
        self.assertEqual(response.status, "200")
        self.assertIsNotNone(response.headers.get("long_hdr", None))
        self.assertIsNotNone(response.headers.get("content-length", None))
        self.assertIsNotNone(response.headers.get("via", None))
        self.assertIsNotNone(response.headers.get("date", None))
        self.assertIsNotNone(response.headers.get("server", None))

    async def _test_initiate_stream_reset_during_sending_data_base(
        self,
        send_frame_func: typing.Callable,
        rcv_rst_expected: bool,
        expected_rst_stream_id: int,
        expected_empty_body: bool,
        second_response_body_size: int,
        rcv_buf_size_threshold: int,
    ):
        self.disable_deproxy_auto_parser()
        tempesta = self.get_tempesta()
        client = self.get_client("deproxy")

        await self.start_all_services()
        # check that rcv buff is lower than approximate data size
        self.assertGreater(
            rcv_buf_size_threshold, client._socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        )
        await self.initiate_h2_connection(client)

        client.readable = lambda: False
        client.stream_id = expected_rst_stream_id
        client.make_request(request=self.get_request)
        await self.assertWaitUntilEqual(
            lambda: self._get_srv_msg_forwarded_stat(tempesta),
            1,
        )

        send_frame_func(self, client, expected_rst_stream_id)

        # check that connection works after reset
        client.stream_id = expected_rst_stream_id + 2
        client.make_request(request=self.get_request)

        # Let Tempesta handle both requests
        await self.assertWaitUntilEqual(
            lambda: self._get_srv_msg_forwarded_stat(tempesta),
            2,
        )
        client.readable = lambda: True

        if rcv_rst_expected:
            await client.wait_for_reset_stream(stream_id=expected_rst_stream_id)

        await client.wait_for_response(n=1),

        partial_response = client._active_responses[expected_rst_stream_id]
        self._check_all_headers_presents_in_partially_received_response(partial_response)
        if expected_empty_body:
            self.assertEqual(partial_response.body, "")

        # Full response has the same headers set as partial, thus use the same method for check
        self._check_all_headers_presents_in_partially_received_response(client.last_response)
        self.assertEqual(client.last_response.body, "q" * second_response_body_size)

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="frame_headers", send_frame_func=_send_headers_frame, rcv_rst_expected=True
            ),
            marks.Param(name="frame_data", send_frame_func=_send_data_frame, rcv_rst_expected=True),
            marks.Param(name="frame_rst", send_frame_func=_send_rst_frame, rcv_rst_expected=False),
        ]
    )
    async def test_initiate_stream_reset_during_sending_resp_headers(
        self, name, send_frame_func, rcv_rst_expected
    ):
        """
        This test verifies that headers will be fully sent by Tempesta when stream has been reset
        by Tempesta or client.

        Send request, stop reading response in then middle of headers reset the stream and wait for
        response.

        Expected:
        Receive one complete response for the second request and one partial response for the first
        request that contains only headers. RST_STREAM also expected for the first request in case
        when stream has been reset by the Tempesta.
        """
        expected_rst_stream_id = 1
        client = self.get_client("deproxy")
        client.rcv_buf_size = 1024
        long_hdr_val_size = 4 * client.rcv_buf_size
        body_size = client.rcv_buf_size * 4
        server = self.get_server("deproxy")
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Long_hdr: "
            + ("x" * (long_hdr_val_size))
            + "\r\n"
            + "Connection: keep-alive\r\n"
            + "Server: deproxy\r\n"
            + f"Content-Length: {body_size}\r\n\r\n"
            + ("q" * body_size)
        )

        await self._test_initiate_stream_reset_during_sending_data_base(
            send_frame_func=send_frame_func,
            rcv_rst_expected=rcv_rst_expected,
            expected_rst_stream_id=1,
            expected_empty_body=True,
            second_response_body_size=body_size,
            rcv_buf_size_threshold=long_hdr_val_size,
        )

    async def test_initiate_stream_reset_during_sending_resp_data(self):
        """
        The same as test_initiate_stream_reset_during_sending_resp_headers but resets the stream
        during receiving body.
        """
        expected_rst_stream_id = 1
        tempesta = self.get_tempesta()
        client = self.get_client("deproxy")
        client.rcv_buf_size = 1024
        body_size = client.rcv_buf_size * 4
        server = self.get_server("deproxy")
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Long_hdr: x\r\n"
            + "Connection: keep-alive\r\n"
            + "Server: deproxy\r\n"
            + f"Content-Length: {body_size}\r\n\r\n"
            + ("q" * body_size)
        )

        await self._test_initiate_stream_reset_during_sending_data_base(
            send_frame_func=TestHalfClosedStreamStateUnexpectedFrames._send_data_frame,
            rcv_rst_expected=True,
            expected_rst_stream_id=1,
            expected_empty_body=False,
            second_response_body_size=body_size,
            rcv_buf_size_threshold=body_size,
        )

    async def test_tempesta_rcv_multiple_data_during_sending_resp_headers(self):
        """
        An endpoint MUST NOT send frames other than PRIORITY on a closed stream.

        Test that Tempesta closes connection when DATA frame is received in closed stream.
        The first sent DATA frame causes transition to closed state, the second MUST cause
        connection close.
        """
        expected_rst_stream_id = 1
        tempesta = self.get_tempesta()
        client = self.get_client("deproxy")
        client.rcv_buf_size = 1024
        long_hdr_size = 4 * client.rcv_buf_size
        server = self.get_server("deproxy")
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Long_hdr: "
            + ("x" * long_hdr_size)
            + "\r\n"
            + "Connection: keep-alive\r\n"
            + "Server: deproxy\r\n"
            + f"Content-Length: {client.rcv_buf_size}\r\n\r\n"
            + ("q" * client.rcv_buf_size)
        )

        await self.start_all_services()
        # check that rcv buff is lower than approximate data size
        self.assertGreater(
            long_hdr_size, client._socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        )
        await self.initiate_h2_connection(client)

        client.readable = lambda: False
        # client opens stream with id 1 and does not close it
        client.make_request(request=self.get_request)
        await self.assertWaitUntilEqual(
            lambda: self._get_srv_msg_forwarded_stat(tempesta),
            1,
        )
        client.send_data_frame(stream_id=expected_rst_stream_id, data=b"a")
        client.send_data_frame(stream_id=expected_rst_stream_id, data=b"b")
        # Let Tempesta handle the new frame. There is no way to ensure
        # that Tempesta received frame, therefore just wait
        await asyncio.sleep(3)
        client.readable = lambda: True

        await client.wait_for_connection_close()

    async def test_initiate_stream_reset_during_sending_resp_headers_and_trigger_stream_cleanup(
        self,
    ):
        """
        This test verifies that headers will be fully sent by Tempesta when stream has been reset
        by Tempesta and triggered stream cleanup that frees memory of closed streams.

        Send request, stop reading response in then middle of headers reset the stream. Then create
        idle streams, when streams are created send request with stream id greater than highest
        idle stream id - this closes all idle streams and triggers cleanup. Wait for response.

        Expected:
        Receive one complete response for the second request and one partial response for the first
        request that contains only headers. RST_STREAM also expected for the first request.
        """
        self.disable_deproxy_auto_parser()
        expected_rst_stream_id = 1
        tempesta = self.get_tempesta()
        tempesta.config.defconfig += "ctrl_frame_rate_multiplier 1000;\n"

        client = self.get_client("deproxy")
        client.rcv_buf_size = 1024
        long_hdr_size = 4 * client.rcv_buf_size
        server = self.get_server("deproxy")
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Long_hdr: "
            + ("x" * long_hdr_size)
            + "\r\n"
            + "Connection: keep-alive\r\n"
            + "Server: deproxy\r\n"
            + f"Content-Length: {client.rcv_buf_size}\r\n\r\n"
            + ("q" * client.rcv_buf_size)
        )

        await self.start_all_services()
        self.assertGreater(
            long_hdr_size, client._socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        )
        await self.initiate_h2_connection(client)

        client.readable = lambda: False
        client.stream_id = expected_rst_stream_id
        client.make_request(request=self.get_request)
        await self.assertWaitUntilEqual(
            lambda: self._get_srv_msg_forwarded_stat(tempesta),
            1,
        )

        # Stream must be not exclusive
        client.send_priority_frame(stream_id=1, depends_on=205, stream_weight=100, exclusive=False)

        # Reset the first stream
        client.send_data_frame(stream_id=expected_rst_stream_id, data=b"a")

        # Create idle streams
        for stream_id in range(3, 201, 2):
            client.send_priority_frame(
                stream_id=stream_id, depends_on=stream_id + 2, stream_weight=2, exclusive=False
            )

        # Initiate idle streams removing to trigger stream clean up
        client.stream_id = 203
        client.make_request(request=self.get_request)
        await self.assertWaitUntilEqual(
            lambda: self._get_srv_msg_forwarded_stat(tempesta),
            2,
        )

        # start receiving data
        client.readable = lambda: True

        await client.wait_for_reset_stream(stream_id=expected_rst_stream_id, timeout=3)

        await client.wait_for_response(n=1),

        partial_response = client._active_responses[expected_rst_stream_id]
        self._check_all_headers_presents_in_partially_received_response(partial_response)
        self.assertEqual(partial_response.body, "")

        # Full response has the same headers set as partial, thus use the same method for check
        self._check_all_headers_presents_in_partially_received_response(client.last_response)
        self.assertEqual(client.last_response.body, "q" * client.rcv_buf_size)


class TestHalfClosedStreamStateWindowUpdate(H2Base):
    async def test_window_update_frame_in_half_closed_state(self):
        """
        An endpoint should receive and accept WINDOW_UPDATE frame
        on half-closed (remote) stream.

        Tempesta must accept WINDOW_UPDATE frame on half-closed
        (remote) stream and continue to send pending data.
        """

        await self.start_all_services()
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
        await client.wait_for_ack_settings()

        client.make_request(self.post_request)
        await client.wait_for_headers_frame(stream_id=1)

        client.h2_connection.increment_flow_control_window(2000)
        client.h2_connection.increment_flow_control_window(2000, stream_id=1)
        client.send_bytes(client.h2_connection.data_to_send())
        client.h2_connection.clear_outbound_data_buffer()

        await client.wait_for_response(2)
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

    async def __setup(self, request=None, expect_response=False):
        await self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + "Server: debian\r\n"
            + "Content-Length: 2000\r\n\r\n"
            + ("x" * 2000)
        )

        await self.initiate_h2_connection(client)
        # create stream and change state machine in H2Connection object
        stream = client.init_stream_for_send(client.stream_id)

        request = request if request is not None else self.post_request
        client.send_headers_frame(
            stream_id=client.stream_id,
            data=client.h2_connection.encoder.encode(request),
            flags=self.flags,
            expect_response=expect_response,
        )
        return client

    async def test_any_frame_between_header_blocks(self):
        """
        Each field block is processed as a discrete unit. Field blocks MUST be
        transmitted as a contiguous sequence of frames, with no interleaved
        frames of any other type or from any other stream. The last frame in a
        sequence of HEADERS or CONTINUATION frames has the END_HEADERS flag set.
        The last frame in a sequence of PUSH_PROMISE or CONTINUATION frames has
        the END_HEADERS flag set. This allows a field block to be logically
        equivalent to a single frame.
        """
        client = await self.__setup()
        client.send_headers_frame(
            stream_id=client.stream_id,
            data=client.h2_connection.encoder.encode(self.post_request),
            flags=["END_HEADERS", "END_STREAM"],
        )
        await client.wait_for_connection_close()
        client.assert_error_code(expected_error_code=ErrorCodes.PROTOCOL_ERROR)

    async def test_headers_frame_for_other_stream_between_header_blocks(self):
        """
        Each field block is processed as a discrete unit. Field blocks MUST be
        transmitted as a contiguous sequence of frames, with no interleaved
        frames of any other type or from any other stream. The last frame in a
        sequence of HEADERS or CONTINUATION frames has the END_HEADERS flag set.
        The last frame in a sequence of PUSH_PROMISE or CONTINUATION frames has
        the END_HEADERS flag set. This allows a field block to be logically
        equivalent to a single frame.
        """
        client = await self.__setup()
        client.send_headers_frame(
            stream_id=client.stream_id + 2,
            data=client.h2_connection.encoder.encode(self.post_request),
            flags=["END_HEADERS", "END_STREAM"],
        )
        await client.wait_for_connection_close()
        client.assert_error_code(expected_error_code=ErrorCodes.PROTOCOL_ERROR)

    async def test_headers_frame_for_other_stream_after_rst(self):
        """
        If the client resets a stream before sending the END_HEADERS flag,
        it causes a protocol violation due to sending a frame other
        than CONTINUATION within a HEADERS block.

        RFC 9113:
        A HEADERS frame without the END_HEADERS flag set
        MUST be followed by a CONTINUATION frame for the same stream.
        A receiver MUST treat the receipt of any other type of frame
        or a frame on a different stream as a connection error of type
        PROTOCOL_ERROR.
        """
        client = await self.__setup()
        client.send_rst_stream_frame(stream_id=1)
        client.stream_id = 3
        client.make_request(self.post_request)
        await client.wait_for_connection_close()
        self.assertIsNone(client.last_response)

    async def test_error_request_between_header_blocks(self):
        """
        Test case when we don't receive END_HEADERS flag
        but have error during processing request.
        """
        client = await self.__setup(self.post_request + [("BAD", "BAD")], True)
        await client.wait_for_response()
        self.assertEqual(client.last_response.status, "400")


class TestTwoHeadersFramesFirstWithoutEndStream(H2Base):
    async def test(self):
        self.disable_deproxy_auto_parser()
        await self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + "Server: debian\r\n"
            + "Content-Length: 2000\r\n\r\n"
            + ("x" * 2000)
        )

        await self.initiate_h2_connection(client)
        # create stream and change state machine in H2Connection object
        stream = client.init_stream_for_send(client.stream_id)

        client.send_headers_frame(
            stream_id=client.stream_id,
            data=client.h2_connection.encoder.encode(self.post_request),
            flags=["END_HEADERS"],
        )

        client.stream_id = 3
        client.make_request(self.post_request)
        await client.wait_for_response()
        self.assertEqual(client.last_response.status, "200")
        self.assertEqual(
            len(client.last_response.body), 2000, "Tempesta did not return full response body."
        )

        client.stream_id = 1
        client.make_request([("header", "x" * 320)])
        await client.wait_for_response()
        self.assertEqual(client.last_response.status, "200")
        self.assertEqual(
            len(client.last_response.body), 2000, "Tempesta did not return full response body."
        )

        client.stream_id = 5
        client.make_request(self.post_request)
        await client.wait_for_response()
        self.assertEqual(client.last_response.status, "200")
        self.assertEqual(
            len(client.last_response.body), 2000, "Tempesta did not return full response body."
        )


class TestIdleState(H2Base):
    async def test_priority_frame_in_idle_state(self):
        """
        An endpoint should receive and accept PRIORITY frame
        on idle stream.
        """

        await self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        client.update_initial_settings()
        client.send_bytes(client.h2_connection.data_to_send())
        await client.wait_for_ack_settings()

        client.send_priority_frame(stream_id=3)
        client.stream_id = 3

        await client.send_request(self.post_request, "200")

    async def test_closing_idle_stream(self):
        """
        The first use of a new stream identifier implicitly closes all
        streams in the "idle" state that might have been initiated by
        that peer with a lower-valued stream identifier.
        """

        await self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        client.update_initial_settings()
        client.send_bytes(client.h2_connection.data_to_send())
        await client.wait_for_ack_settings()

        client.send_priority_frame(stream_id=7)
        client.stream_id = 11
        await client.send_request(self.post_request, "200")

        """
        Idle stream with id == 7 should be moved to closed state
        during previous request. Headers frames are not allowed in
        the closed state. Connection is closed with PROTOCOL_ERROR
        """
        client.send_headers_frame(
            stream_id=7,
            data=client.h2_connection.encoder.encode(self.post_request),
            flags=["END_HEADERS"],
        )

        await client.wait_for_connection_close()
        client.assert_error_code(expected_error_code=ErrorCodes.PROTOCOL_ERROR)

    async def test_not_closing_idle_stream(self):
        """
        The first use of a new stream identifier implicitly closes all
        streams in the "idle" state that might have been initiated by
        that peer with a lower-valued stream identifier and not closes
        with a greater one.
        """

        await self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        client.update_initial_settings()
        client.send_bytes(client.h2_connection.data_to_send())
        await client.wait_for_ack_settings()

        client.send_priority_frame(stream_id=17)
        client.stream_id = 11
        await client.send_request(self.post_request, "200")

        client.stream_id = 17
        await client.send_request(self.post_request, "200")

    async def test_rst_frame_for_idle_stream(self):
        """
        Send priority frame to create idle stream.
        Then open stream with invalid HEADERS frame.
        Check for connection close.
        """
        await self.start_all_services()
        client = self.get_client("deproxy")
        client.parsing = False

        client.update_initial_settings()
        client.send_bytes(client.h2_connection.data_to_send())
        await client.wait_for_ack_settings()

        stream = client.init_stream_for_send(client.stream_id)
        client.h2_connection.state_machine.process_input(ConnectionInputs.SEND_HEADERS)

        client.send_priority_frame(
            stream_id=stream.stream_id, depends_on=5, stream_weight=255, exclusive=False
        )
        client.send_headers_frame(
            stream_id=stream.stream_id,
            stream_weight=255,
            depends_on=stream.stream_id,
            exclusive=False,
            data=client.h2_connection.encoder.encode(self.get_request),
            flags=["END_HEADERS", "END_STREAM", "PRIORITY"],
        )

        await client.wait_for_connection_close()
