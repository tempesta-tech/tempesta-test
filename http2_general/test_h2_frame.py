"""Functional tests for h2 frames."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

from h2.connection import ConnectionInputs
from h2.errors import ErrorCodes
from h2.exceptions import StreamClosedError
from h2.settings import SettingCodes
from h2.stream import StreamInputs
from hpack import HeaderTuple
from hyperframe.frame import ContinuationFrame, DataFrame, HeadersFrame, SettingsFrame

from framework import deproxy_client, stateful
from helpers import util, tf_cfg
from helpers.deproxy import HttpMessage
from helpers.networker import NetWorker
from http2_general.helpers import H2Base
from test_suite import checks_for_tests as checks
from test_suite import marks


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

    def test_empty_data_frame_mixed(self):
        """
        Send request with empty DATA frame after non empty.
        Tempesta treats empty DATA frames without END_STREAM as inavalid.
        """
        self.start_all_services()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.parsing = False
        request_body = "123"

        deproxy_cl.update_initial_settings()
        deproxy_cl.send_bytes(deproxy_cl.h2_connection.data_to_send())
        deproxy_cl.wait_for_ack_settings()

        deproxy_cl.make_request(request=self.post_request, end_stream=False)
        deproxy_cl.make_request(request=request_body, end_stream=False)
        deproxy_cl.send_bytes(DataFrame(stream_id=1, data=b"").serialize(), expect_response=False)
        deproxy_cl.send_bytes(DataFrame(stream_id=1, data=b"").serialize(), expect_response=False)

        self.assertTrue(deproxy_cl.wait_for_connection_close(timeout=5))
        self.assertIn(ErrorCodes.PROTOCOL_ERROR, deproxy_cl.error_codes)

    def test_empty_data_frame(self):
        """
        Send request with empty DATA frame.
        Tempesta treats empty DATA frames without END_STREAM as inavalid.
        """
        self.start_all_services()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.parsing = False
        request_body = "123"

        deproxy_cl.update_initial_settings()
        deproxy_cl.send_bytes(deproxy_cl.h2_connection.data_to_send())
        deproxy_cl.wait_for_ack_settings()

        deproxy_cl.make_request(request=self.post_request, end_stream=False)
        deproxy_cl.send_bytes(DataFrame(stream_id=1, data=b"").serialize())

        self.assertTrue(deproxy_cl.wait_for_connection_close(timeout=5))
        self.assertIn(ErrorCodes.PROTOCOL_ERROR, deproxy_cl.error_codes)

    def test_opening_same_stream_after_invalid(self):
        """
        Try to open stream with invalid HEADERS frame.
        Then try to open stream with same id.
        Connection should be closed.
        """
        self.start_all_services()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.parsing = False

        deproxy_cl.update_initial_settings()
        deproxy_cl.send_bytes(deproxy_cl.h2_connection.data_to_send())
        deproxy_cl.wait_for_ack_settings()

        stream = deproxy_cl.init_stream_for_send(deproxy_cl.stream_id)
        deproxy_cl.h2_connection.state_machine.process_input(ConnectionInputs.SEND_HEADERS)

        hf_bad = HeadersFrame(
            stream_id=stream.stream_id,
            data=deproxy_cl.h2_connection.encoder.encode(self.get_request),
            flags=["END_HEADERS", "END_STREAM", "PRIORITY"],
        )

        hf_bad.stream_weight = 255
        hf_bad.depends_on = stream.stream_id
        hf_bad.exclusive = False

        hf_good = HeadersFrame(
            stream_id=stream.stream_id,
            data=deproxy_cl.h2_connection.encoder.encode(self.get_request),
            flags=["END_HEADERS", "END_STREAM"],
        )

        deproxy_cl.send_bytes(hf_bad.serialize() + hf_good.serialize())
        self.assertTrue(deproxy_cl.wait_for_reset_stream(stream.stream_id))
        self.assertTrue(deproxy_cl.wait_for_connection_close())

    def test_multiple_empty_headers_frames(self):
        """
        An endpoint that receives a HEADERS frame without the END_STREAM flag set
        after receiving the HEADERS frame that opens a request or after receiving
        a final (non-informational) status code MUST treat the corresponding
        request or response as malformed (Section 8.1.1).
        """
        self.start_all_services()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.parsing = False

        self.initiate_h2_connection(deproxy_cl)
        # create stream and change state machine in H2Connection object
        stream = deproxy_cl.init_stream_for_send(deproxy_cl.stream_id)

        hf_empty = HeadersFrame(
            stream_id=1,
        )

        hf_end = HeadersFrame(
            stream_id=1,
            data=deproxy_cl.h2_connection.encoder.encode(self.get_request),
            flags=["END_HEADERS", "END_STREAM"],
        )

        for i in range(20):
            deproxy_cl.send_bytes(hf_empty.serialize())
        deproxy_cl.send_bytes(hf_end.serialize(), expect_response=True)

        self.assertTrue(deproxy_cl.wait_for_connection_close(timeout=5))
        self.assertIn(ErrorCodes.PROTOCOL_ERROR, deproxy_cl.error_codes)

    @marks.Parameterize.expand(
        [
            marks.Param(name="end_headers", flags=["END_HEADERS"]),
            marks.Param(name="no_end_headers", flags=[]),
        ]
    )
    def test_empty_headers_frame(self, name, flags):
        """
        An endpoint that receives a HEADERS frame without the END_STREAM flag set
        after receiving the HEADERS frame that opens a request or after receiving
        a final (non-informational) status code MUST treat the corresponding
        request or response as malformed (Section 8.1.1).
        """
        self.start_all_services()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.parsing = False

        self.initiate_h2_connection(deproxy_cl)
        # create stream and change state machine in H2Connection object
        stream = deproxy_cl.init_stream_for_send(deproxy_cl.stream_id)

        hf_start = HeadersFrame(
            stream_id=1,
            data=deproxy_cl.h2_connection.encoder.encode(self.get_request),
            flags=flags,
        )
        hf_empty = HeadersFrame(stream_id=1)
        deproxy_cl.send_bytes(hf_start.serialize())
        deproxy_cl.send_bytes(hf_empty.serialize())

        self.assertTrue(deproxy_cl.wait_for_connection_close(timeout=5))
        self.assertIn(ErrorCodes.PROTOCOL_ERROR, deproxy_cl.error_codes)

    def test_empty_headers_empty_continuation_multiple(self):
        """
        Test flooding multiple CONTINUATION with END_HEADERS
        that sends after empty HEADERS frame.
        """
        self.start_all_services()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.parsing = False

        self.initiate_h2_connection(deproxy_cl)
        # create stream and change state machine in H2Connection object
        stream = deproxy_cl.init_stream_for_send(deproxy_cl.stream_id)

        hf_empty = HeadersFrame(stream_id=1)
        cf_empty = ContinuationFrame(stream_id=1, flags=["END_HEADERS"])
        deproxy_cl.send_bytes(hf_empty.serialize())
        deproxy_cl.send_bytes(cf_empty.serialize())
        deproxy_cl.send_bytes(cf_empty.serialize())

        self.assertTrue(deproxy_cl.wait_for_connection_close(timeout=5))
        self.assertIn(ErrorCodes.PROTOCOL_ERROR, deproxy_cl.error_codes)

    def test_empty_continuation_end_headers(self):
        """
        Test handling empty CONTINUATION frame with END_HEADERS
        END_HEADERS that used for closing HEADERS block.
        """
        self.start_all_services()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.parsing = False

        self.initiate_h2_connection(deproxy_cl)
        # create stream and change state machine in H2Connection object
        stream = deproxy_cl.init_stream_for_send(deproxy_cl.stream_id)

        hf_start = HeadersFrame(
            stream_id=1, data=deproxy_cl.h2_connection.encoder.encode(self.post_request)
        )
        cf_empty = ContinuationFrame(stream_id=1, flags=["END_HEADERS"])
        df_end = DataFrame(stream_id=1, data=b"", flags=["END_STREAM"])

        deproxy_cl.send_bytes(hf_start.serialize())
        deproxy_cl.send_bytes(cf_empty.serialize(), expect_response=False)
        deproxy_cl.send_bytes(df_end.serialize(), expect_response=True)
        self.__assert_test(client=deproxy_cl, request_body="", request_number=1)

    def test_empty_continuation_frame(self):
        """
        Test handling empty CONTINUATION frame w/o END_HEADERS.
        PROTOCOL_ERROR is expected.
        """
        self.start_all_services()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.parsing = False

        self.initiate_h2_connection(deproxy_cl)
        # create stream and change state machine in H2Connection object
        stream = deproxy_cl.init_stream_for_send(deproxy_cl.stream_id)

        hf_start = HeadersFrame(
            stream_id=1, data=deproxy_cl.h2_connection.encoder.encode(self.post_request)
        )
        cf_empty = ContinuationFrame(stream_id=1)
        cf_empty_end = ContinuationFrame(stream_id=1, flags=["END_HEADERS"])
        df_end = DataFrame(stream_id=1, data=b"", flags=["END_STREAM"])

        deproxy_cl.send_bytes(hf_start.serialize())
        deproxy_cl.send_bytes(cf_empty.serialize(), expect_response=False)
        deproxy_cl.send_bytes(cf_empty_end.serialize(), expect_response=False)
        deproxy_cl.send_bytes(df_end.serialize(), expect_response=False)

        self.assertTrue(deproxy_cl.wait_for_connection_close(timeout=5))
        self.assertIn(ErrorCodes.PROTOCOL_ERROR, deproxy_cl.error_codes)

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
        self.disable_deproxy_auto_parser()
        client = self.get_client("deproxy")
        client.parsing = False

        self.start_all_services()
        self.initiate_h2_connection(client)

        # client opens stream with id 1 and does not close it
        client.make_request(request=self.post_request, end_stream=False)

        # client send invalid request and Tempesta returns RST_STREAM
        stream_with_rst = 3
        client.stream_id = stream_with_rst
        client.send_request(self.get_request + [("x-forwarded-for", "1.1.1.1.1.1")], "400")

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
            client.wait_for_connection_close(),
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

        self.assertTrue(client.wait_for_connection_close(), "Tempesta did not send GOAWAY frame.")
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

    def test_trailer_header_frame_without_end_stream(self):
        """
        The RFC allows 2 headers frame in one stream - first for headers and second for trailers.
        """
        client = self.get_client("deproxy")

        self.start_all_services()
        self.initiate_h2_connection(client)

        client.make_request(self.post_request, end_stream=False)
        hf = HeadersFrame(
            stream_id=client.stream_id,
            data=client.h2_connection.encoder.encode([("header1", "header value1")]),
            flags=["END_HEADERS"],
        )
        client.send_bytes(data=hf.serialize(), expect_response=False)

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


class TestH2FrameEnabledDisabledTsoGroGsoBase(H2Base):
    def setup_tests(self):
        self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        client.update_initial_settings(header_table_size=512)
        client.send_bytes(client.h2_connection.data_to_send())
        client.wait_for_ack_settings()
        client.h2_connection.clear_outbound_data_buffer()

        return client, server


DEFAULT_MTU = 1500


class TestH2FrameEnabledDisabledTsoGroGso(TestH2FrameEnabledDisabledTsoGroGsoBase, NetWorker):
    def test_headers_frame_with_continuation(self):
        client, server = self.setup_tests()
        self.run_test_tso_gro_gso_disabled(
            client, server, self._test_headers_frame_with_continuation, DEFAULT_MTU
        )
        self.run_test_tso_gro_gso_enabled(
            client, server, self._test_headers_frame_with_continuation, DEFAULT_MTU
        )

    def test_headers_frame_without_continuation(self):
        client, server = self.setup_tests()
        self.run_test_tso_gro_gso_disabled(
            client, server, self._test_headers_frame_without_continuation, DEFAULT_MTU
        )
        self.run_test_tso_gro_gso_enabled(
            client, server, self._test_headers_frame_without_continuation, DEFAULT_MTU
        )

    def test_mixed_frames_long_headers_disabled(self):
        config = self.get_tempesta().config.defconfig
        config += "ctrl_frame_rate_multiplier 16;\n"
        self.get_tempesta().config.set_defconfig(config)

        client, server = self.setup_tests()
        self.run_test_tso_gro_gso_disabled(
            client, server, self._test_mixed_frames_long_headers, DEFAULT_MTU
        )

    def test_mixed_frames_long_headers_enabled(self):
        config = self.get_tempesta().config.defconfig
        config += "ctrl_frame_rate_multiplier 16;\n"
        self.get_tempesta().config.set_defconfig(config)

        client, server = self.setup_tests()
        self.run_test_tso_gro_gso_enabled(
            client, server, self._test_mixed_frames_long_headers, DEFAULT_MTU
        )

    def test_data_frame(self):
        client, server = self.setup_tests()
        self.run_test_tso_gro_gso_disabled(client, server, self._test_data_frame, DEFAULT_MTU)
        self.run_test_tso_gro_gso_enabled(client, server, self._test_data_frame, DEFAULT_MTU)

    def test_headers_frame_for_local_resp_invalid_req_d(self):
        client, server = self.setup_tests()
        self.run_test_tso_gro_gso_disabled(
            client, server, self._test_headers_frame_for_local_resp_invalid_req, DEFAULT_MTU
        )

    def test_headers_frame_for_local_resp_invalid_req_e(self):
        client, server = self.setup_tests()
        self.run_test_tso_gro_gso_enabled(
            client, server, self._test_headers_frame_for_local_resp_invalid_req, DEFAULT_MTU
        )

    def _test_headers_frame_for_local_resp_invalid_req(self, client, server):
        client.send_request(
            request=[
                HeaderTuple(":authority", "bad.com"),
                HeaderTuple(":path", "/"),
                HeaderTuple(":scheme", "https"),
                HeaderTuple(":method", "GET"),
            ],
            expected_status_code="403",
        )

    def __prepare_hf_to_send(self, client):
        # create stream and change state machine in H2Connection object
        stream = client.init_stream_for_send(client.stream_id)

        hf = HeadersFrame(
            stream_id=stream.stream_id,
            data=client.h2_connection.encoder.encode(self.post_request),
            flags=["END_STREAM", "END_HEADERS"],
        )
        client.stream_id += 2

        return hf.serialize()

    def __send_header_and_data_frames_with_mixed_frames(
        self, client, server, count, extra_settings_cnt, header_len, body_len, timeout=5
    ):
        header = ("qwerty", "x" * header_len)
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + "Server: debian\r\n"
            + f"{header[0]}: {header[1]}\r\n"
            + f"Content-Length: {body_len}\r\n\r\n"
            + ("x" * body_len)
        )

        data_to_send = b""
        for _ in range(count):
            data_to_send += self.__prepare_hf_to_send(client)

        client.send_bytes(data_to_send, expect_response=False)
        for _ in range(extra_settings_cnt):
            client.send_bytes(
                SettingsFrame(
                    stream_id=0, settings={SettingCodes.INITIAL_WINDOW_SIZE: 300}
                ).serialize(),
                expect_response=False,
            )
        client.valid_req_num += count
        self.assertTrue(client.wait_for_response(timeout))
        self.assertFalse(client.connection_is_closed())

        for i in range(count):
            self.assertEqual(client.responses[i].status, "200", "Status code mismatch.")
            self.assertIsNotNone(client.responses[i].headers.get(header[0]))
            self.assertEqual(len(client.responses[i].headers.get(header[0])), len(header[1]))
            self.assertEqual(
                len(client.responses[i].body),
                body_len,
                "Tempesta did not return full response body.",
            )

        # First ack was received when we establish connection
        self.assertTrue(
            util.wait_until(
                lambda: client.ack_cnt - 1 != extra_settings_cnt,
                timeout,
                abort_cond=lambda: client.state != stateful.STATE_STARTED,
            )
        )

    def _test_mixed_frames_long_headers(self, client, server):
        """
        Other frames (from any stream) MUST NOT occur between
        the HEADERS frame and any CONTINUATION frames that might
        follow.
        """
        self.__send_header_and_data_frames_with_mixed_frames(client, server, 3, 50, 50000, 1000)

    def _test_data_frame(self, client, server):
        self.__send_header_and_data_frames_with_mixed_frames(client, server, 1, 0, 50000, 100000)

    def _test_headers_frame_with_continuation(self, client, server):
        self.__send_header_and_data_frames_with_mixed_frames(client, server, 1, 0, 50000, 0)

    def _test_headers_frame_without_continuation(self, client, server):
        self.__send_header_and_data_frames_with_mixed_frames(client, server, 1, 0, 1000, 0)


class TestH2FrameEnabledDisabledTsoGroGsoStickyCookie(
    TestH2FrameEnabledDisabledTsoGroGsoBase, NetWorker
):
    tempesta = {
        "config": """
            listen 443 proto=h2;
            srv_group default {
                server ${server_ip}:8000;
            }
            frang_limits {http_strict_host_checking false;}
            vhost v_good {
                proxy_pass default;
                sticky {
                    sticky_sessions;
                    cookie enforce max_misses=0;
                    secret "f00)9eR59*_/22";
                }
            }
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;
            cache 1;
            cache_fulfill * *;
            block_action attack reply;
            block_action error reply;
            http_chain {
                host == "bad.com"   -> block;
                host == "example.com" -> v_good;
            }
        """
    }

    def test_headers_frame_for_local_resp_sticky_cookie_short(self):
        client, server = self.setup_tests()
        self.run_test_tso_gro_gso_disabled(
            client, server, self._test_headers_frame_for_local_resp_sticky_cookie_short, DEFAULT_MTU
        )
        self.run_test_tso_gro_gso_enabled(
            client, server, self._test_headers_frame_for_local_resp_sticky_cookie_short, DEFAULT_MTU
        )

    def test_headers_frame_for_local_resp_sticky_cookie_long(self):
        client, server = self.setup_tests()
        self.run_test_tso_gro_gso_disabled(
            client, server, self._test_headers_frame_for_local_resp_sticky_cookie_long, DEFAULT_MTU
        )
        self.run_test_tso_gro_gso_enabled(
            client, server, self._test_headers_frame_for_local_resp_sticky_cookie_long, DEFAULT_MTU
        )

    def _test_headers_frame_for_local_resp_sticky_cookie_short(self, client, server):
        self._test_headers_frame_for_local_resp_sticky_cookie(client, server, 1000, 0)

    def _test_headers_frame_for_local_resp_sticky_cookie_long(self, client, server):
        self._test_headers_frame_for_local_resp_sticky_cookie(client, server, 50000, 50000)

    def _test_headers_frame_for_local_resp_sticky_cookie(
        self, client, server, header_len, body_len
    ):
        header = ("qwerty", "x" * header_len)
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + "Server: debian\r\n"
            + f"{header[0]}: {header[1]}\r\n"
            + f"Content-Length: {body_len}\r\n\r\n"
            + ("x" * body_len)
        )

        client.send_request(request=self.post_request, expected_status_code="302")
        self.post_request.append(HeaderTuple("Cookie", client.last_response.headers["set-cookie"]))
        client.send_request(request=self.post_request, expected_status_code="200")
        self.post_request.pop()


class TestH2FrameEnabledDisabledTsoGroGsoCache(TestH2FrameEnabledDisabledTsoGroGsoBase, NetWorker):
    tempesta = {
        "config": """
            listen 443 proto=h2;
            srv_group default {
                server ${server_ip}:8000;
            }
            frang_limits {http_strict_host_checking false;}
            vhost v_good {
                proxy_pass default;
            }
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;
            cache 1;
            cache_fulfill * *;
            cache_methods GET;
            block_action attack reply;
            block_action error reply;
            http_chain {
                host == "bad.com"   -> block;
                host == "example.com" -> v_good;
            }
        """
    }

    def test_headers_frame_for_local_resp_cache_304_short(self):
        client, server = self.setup_tests()
        self.run_test_tso_gro_gso_disabled(
            client, server, self._test_headers_frame_for_local_resp_cache_304_short, DEFAULT_MTU
        )
        self.run_test_tso_gro_gso_enabled(
            client, server, self._test_headers_frame_for_local_resp_cache_304_short, DEFAULT_MTU
        )

    def test_headers_frame_for_local_resp_cache_200_short(self):
        client, server = self.setup_tests()
        self.run_test_tso_gro_gso_disabled(
            client, server, self._test_headers_frame_for_local_resp_cache_200_short, DEFAULT_MTU
        )
        self.run_test_tso_gro_gso_enabled(
            client, server, self._test_headers_frame_for_local_resp_cache_200_short, DEFAULT_MTU
        )

    def test_headers_frame_for_local_resp_cache_304_long(self):
        client, server = self.setup_tests()
        self.run_test_tso_gro_gso_disabled(
            client, server, self._test_headers_frame_for_local_resp_cache_304_long, DEFAULT_MTU
        )
        self.run_test_tso_gro_gso_enabled(
            client, server, self._test_headers_frame_for_local_resp_cache_304_long, DEFAULT_MTU
        )

    def test_headers_frame_for_local_resp_cache_200_long(self):
        client, server = self.setup_tests()
        self.run_test_tso_gro_gso_disabled(
            client, server, self._test_headers_frame_for_local_resp_cache_200_long, DEFAULT_MTU
        )
        self.run_test_tso_gro_gso_enabled(
            client, server, self._test_headers_frame_for_local_resp_cache_200_long, DEFAULT_MTU
        )

    def _test_headers_frame_for_local_resp_cache_304_short(self, client, server):
        self._test_headers_frame_for_local_resp_cache(
            client, server, 1000, 0, "Mon, 12 Dec 3034 13:59:39 GMT", "304"
        )

    def _test_headers_frame_for_local_resp_cache_200_short(self, client, server):
        self._test_headers_frame_for_local_resp_cache(
            client, server, 1000, 0, "Mon, 12 Dec 2020 13:59:39 GMT", "200"
        )

    def _test_headers_frame_for_local_resp_cache_304_long(self, client, server):
        self._test_headers_frame_for_local_resp_cache(
            client, server, 50000, 100000, "Mon, 12 Dec 3034 13:59:39 GMT", "304"
        )

    def _test_headers_frame_for_local_resp_cache_200_long(self, client, server):
        self._test_headers_frame_for_local_resp_cache(
            client, server, 50000, 100000, "Mon, 12 Dec 2020 13:59:39 GMT", "200"
        )

    def _test_headers_frame_for_local_resp_cache(
        self, client, server, header_len, body_len, date, status_code
    ):
        header = ("qwerty", "x" * header_len)
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + "Server: debian\r\n"
            + f"{header[0]}: {header[1]}\r\n"
            + f"Content-Length: {body_len}\r\n\r\n"
            + ("x" * body_len)
        )

        headers = [
            HeaderTuple(":authority", "example.com"),
            HeaderTuple(":path", "/"),
            HeaderTuple(":scheme", "https"),
            HeaderTuple(":method", "GET"),
        ]

        client.send_request(request=headers, expected_status_code="200")

        headers.append(HeaderTuple("if-modified-since", date))
        client.send_request(request=headers, expected_status_code=status_code)


class TestPostponedFrames(H2Base, NetWorker):
    """
    According RFC 9113:
    If the END_HEADERS flag is not set, this frame MUST be followed by another CONTINUATION frame.
    A receiver MUST treat the receipt of any other type of frame or a frame on a different stream
    as a connection error (Section 5.4.1) of type PROTOCOL_ERROR.
    This class checks that Tempesta FW doesn't violate this rule.
    """

    def _ping(self, client):
        client.h2_connection.ping(opaque_data=b"\x00\x01\x02\x03\x04\x05\x06\x07")
        client.send_bytes(client.h2_connection.data_to_send())
        client.h2_connection.clear_outbound_data_buffer()

    def _test(self, client, server):
        client.update_initial_settings(initial_window_size=0)
        client.send_bytes(client.h2_connection.data_to_send())
        self.assertTrue(client.wait_for_ack_settings())

        ping_count = 500

        stream_id = client.stream_id
        client.make_request(self.get_request)
        for _ in range(0, ping_count):
            self._ping(client)

        self.assertTrue(client.wait_for_headers_frame(stream_id))
        self.assertTrue(client.wait_for_ping_frames(ping_count))

        client.send_settings_frame(initial_window_size=65535)
        self.assertTrue(client.wait_for_ack_settings())

        for _ in range(0, ping_count):
            self._ping(client)

        self.assertTrue(client.wait_for_headers_frame(stream_id))
        self.assertTrue(client.wait_for_ping_frames(2 * ping_count))

        self.assertTrue(client.wait_for_response())
        self.assertTrue(client.last_response.status, "200")

    @marks.Parameterize.expand(
        [
            marks.Param(name="headers", header="a" * 30000, token="value"),
            marks.Param(name="trailers", header="value", token="a" * 30000),
        ]
    )
    @NetWorker.set_mtu(
        nodes=[
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Tempesta", "ip"),
                "mtu": 100,
            }
        ]
    )
    def test(self, name, header, token):
        config = self.get_tempesta().config.defconfig
        config += "ctrl_frame_rate_multiplier 256;\n"
        self.get_tempesta().config.set_defconfig(config)
        self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")
        server.set_response(
            "HTTP/1.1 200 OK\n"
            + "Transfer-Encoding: chunked\n"
            + f"header: {header}"
            + "Trailer: X-Token\r\n\r\n"
            + "10\r\n"
            + "abcdefghijklmnop\r\n"
            + "0\r\n"
            + f"X-Token: {token}\r\n\r\n"
        )

        self.run_test_tso_gro_gso_disabled(client, server, self._test, 100)
