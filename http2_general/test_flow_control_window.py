"""Functional tests for flow control window."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from h2.errors import ErrorCodes
from hyperframe.frame import DataFrame

from helpers import analyzer, remote, util
from helpers.deproxy import HttpMessage
from http2_general.helpers import H2Base
from test_suite import asserts, marks


def encode_chunked(data, chunk_size=256):
    result = ""
    while len(data):
        chunk, data = data[:chunk_size], data[chunk_size:]
        result += f"{hex(len(chunk))[2:]}\r\n"
        result += f"{chunk}\r\n"
    return result + "0\r\n\r\n"


class TestFlowControl(H2Base, asserts.Sniffer):
    def _initiate_client_and_server(self, response: str):
        self.start_all_services()

        server = self.get_server("deproxy")
        server.set_response(response)

        client = self.get_client("deproxy")
        client.auto_flow_control = False
        client.update_initial_settings(initial_window_size=0)
        client.send_bytes(client.h2_connection.data_to_send())
        client.wait_for_ack_settings()

        return client, server

    def _wait_data_frame_and_check_response(self, client, response_body: str, valid_req_num: int):
        client.valid_req_num = valid_req_num  # change the expected number of responses
        client.wait_for_response(strict=True)

        self.assertEqual(client.last_response.status, "200", "Status code mismatch.")
        self.assertEqual(
            client.last_response.body,
            response_body,
            "Tempesta returned invalid response body.",
        )

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="no_trailer_in_response",
                response_str="HTTP/1.1 200 OK\r\n"
                + f"Date: {HttpMessage.date_time_string()}\r\n"
                + "Server: debian\r\n"
                + "Content-Length: 2000\r\n\r\n"
                + ("x" * 2000),
            ),
            marks.Param(
                name="trailer_in_response",
                response_str="HTTP/1.1 200 OK\r\n"
                + "Content-type: text/html\r\n"
                + f"Date: {HttpMessage.date_time_string()}\r\n"
                + "Server: debian\r\n"
                + "Transfer-Encoding: chunked\r\n"
                + "Trailer: X-Token\r\n\r\n"
                + encode_chunked(2000 * "x", 16)[:-2]
                + "X-Token: value\r\n\r\n",
            ),
        ]
    )
    def test_single_stream(self, name, response_str):
        """
        Client sets SETTINGS_INITIAL_WINDOW_SIZE = 0 bytes and backend returns response
        with 2k bytes body. Client send several WindowUpdate with 1k the flow control window.
        Tempesta must be forwarded 2 DATA frames with 1k bytes.
        1. Client make request and wait for HEADERS frame;
        2. Tempesta forward request to server and receive response with 2k body;
        3. Tempesta forward only HEADERS frame without DATA frame and
           wait for WindowUpdate from client;
        4. Client send WindowUpdate with 1K flow control window after receiving HEADERS frame;
        5. Tempesta forward first DATA frame with 1k bytes;
        6. Client send WindowUpdate with 1K flow control window after receiving first DATA frame;
        7. Tempesta forward second DATA frame with 1k bytes;

        We also check how it works with trailers, because appropriate PR in Tempesta FW had
        errors.
        """
        client, server = self._initiate_client_and_server(response=(response_str))

        client.last_response_buffer = bytes()  # clearing the buffer after exchanging settings
        client.make_request(self.get_request)
        self.assertTrue(client.wait_for_headers_frame(stream_id=1))

        # client send WindowUpdate with 1k flow control window
        client.increment_flow_control_window(stream_id=1, flow_controlled_length=1000)

        # wait for a DATA frame with 1k bytes in response buffer
        self.assertTrue(
            util.wait_until(lambda: not (b"x" * 1000) in client.last_response_buffer),
            "Tempesta did not send first DATA frame after receiving WindowUpdate frame.",
        )

        # client send WindowUpdate with 1k flow control window
        client.increment_flow_control_window(stream_id=1, flow_controlled_length=1000)
        self._wait_data_frame_and_check_response(client, response_body="x" * 2000, valid_req_num=1)

    def test_several_stream(self):
        """
        Client sets SETTINGS_INITIAL_WINDOW_SIZE = 0 bytes and make 2 requests to different
        response. Tempesta must wait for increase window for each stream.
        """
        self.disable_deproxy_auto_parser()
        client, server = self._initiate_client_and_server(
            response=(
                "HTTP/1.1 200 OK\r\n"
                + f"Date: {HttpMessage.date_time_string()}\r\n"
                + "Server: debian\r\n"
                + "Content-Length: 14\r\n\r\n"
                + "First response"
            )
        )

        client.last_response_buffer = bytes()  # clearing the buffer after exchanging settings
        # send request and wait for an only HEADERS frame for stream 1
        client.make_request(self.get_request)
        self.assertTrue(client.wait_for_headers_frame(stream_id=1))

        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + "Server: debian\r\n"
            + "Content-Length: 15\r\n\r\n"
            + "Second response"
        )

        # send request and wait for an only HEADERS frame for stream 3
        client.make_request(self.get_request)
        self.assertTrue(client.wait_for_headers_frame(stream_id=3))

        # send WindowUpdate for stream 1 and wait for a DATA frame for it
        client.increment_flow_control_window(stream_id=1, flow_controlled_length=14)
        self._wait_data_frame_and_check_response(
            client, response_body="First response", valid_req_num=1
        )

        # send WindowUpdate for stream 3 and wait for a DATA frame for it
        client.increment_flow_control_window(stream_id=3, flow_controlled_length=15)
        self._wait_data_frame_and_check_response(
            client, response_body="Second response", valid_req_num=2
        )

    def test_not_blocked_continuation_frame(self):
        """
        1. Client sets SETTINGS_INITIAL_WINDOW_SIZE = 0 bytes;
        2. Server return response with body and headers greater than MAX_FRAME_SIZE.
        3. Tempesta must forward HEADERS and CONTINUATION frame and wait for a WindowUpdate.
        4. Client send WindowUpdate and wait for a DATA frame.
        """
        client, server = self._initiate_client_and_server(
            response=(
                "HTTP/1.1 200 OK\r\n"
                + f"Date: {HttpMessage.date_time_string()}\r\n"
                + "Server: debian\r\n"
                + f"X-My-Hdr: {'a' * 20000}\r\n"
                + "Content-Length: 100\r\n\r\n"
                + ("x" * 100)
            )
        )

        # send request and wait for a HEADERS + CONTINUATION frames
        client.make_request(self.get_request)
        self.assertTrue(client.wait_for_headers_frame(stream_id=1))

        client.increment_flow_control_window(stream_id=1, flow_controlled_length=100)
        self._wait_data_frame_and_check_response(client, response_body="x" * 100, valid_req_num=1)

    def test_not_blocked_settings_frame(self):
        """
        1. Client sets SETTINGS_INITIAL_WINDOW_SIZE = 0 bytes;
        2. Server return response with body.
        3. Tempesta must forward HEADERS frame and wait for a WindowUpdate.
        4. Client send SETTINGS frame and wait for a SETTINGS frame with ack settings from
           Tempesta.
        5. Client send WindowUpdate and wait for a DATA frame.
        """
        client, server = self._initiate_client_and_server(
            response=(
                "HTTP/1.1 200 OK\r\n"
                + f"Date: {HttpMessage.date_time_string()}\r\n"
                + "Server: debian\r\n"
                + "Content-Length: 100\r\n\r\n"
                + ("x" * 100)
            )
        )

        client.last_response_buffer = bytes()  # clearing the buffer after exchanging settings
        client.make_request(self.get_request)
        self.assertTrue(client.wait_for_headers_frame(stream_id=1))

        client.send_settings_frame(header_table_size=2048)
        self.assertTrue(
            client.wait_for_ack_settings(),
            "Tempesta did not forward the SETTINGS frame when the window size is 0.",
        )

        client.increment_flow_control_window(stream_id=1, flow_controlled_length=100)
        self._wait_data_frame_and_check_response(client, response_body="x" * 100, valid_req_num=1)

    def test_not_blocked_rst_frame(self):
        """
        1. Client sets SETTINGS_INITIAL_WINDOW_SIZE = 0 bytes;
        2. Server return response with body.
        3. Tempesta must forward HEADERS frame and wait for a WindowUpdate.
        4. Client send DATA frame in this stream and wait for RST_STREAM.
        """
        client, server = self._initiate_client_and_server(
            response=(
                "HTTP/1.1 200 OK\r\n"
                + f"Date: {HttpMessage.date_time_string()}\r\n"
                + "Server: debian\r\n"
                + "Content-Length: 100\r\n\r\n"
                + ("x" * 100)
            )
        )

        client.make_request(self.get_request)
        self.assertTrue(client.wait_for_headers_frame(stream_id=1))

        # send DATA frame for GET request and wait for RST_STREAM
        client.send_bytes(DataFrame(stream_id=1, data=b"123", flags=["END_STREAM"]).serialize())

        self.assertTrue(
            client.wait_for_reset_stream(stream_id=1),
            "Tempesta did not forward the RST_STREAM frame when a window size is 0.",
        )
        self.assertFalse(
            client.connection_is_closed(),
            "Tempesta closed connection when sending the RST_STREAM with a window size is 0.",
        )

    def test_not_blocked_goaway_frame(self):
        """
        1. Client sets SETTINGS_INITIAL_WINDOW_SIZE = 0 bytes;
        2. Server return response with body.
        3. Tempesta must forward HEADERS frame and wait for a WindowUpdate.
        4. Client send DATA frame with stream_id 0 and wait for the GOAWAY frame.
        """
        sniffer = analyzer.Sniffer(remote.client, "Client", timeout=5, ports=(443,))
        sniffer.start()

        client, server = self._initiate_client_and_server(
            response=(
                "HTTP/1.1 200 OK\r\n"
                + f"Date: {HttpMessage.date_time_string()}\r\n"
                + "Server: debian\r\n"
                + "Content-Length: 100\r\n\r\n"
                + ("x" * 100)
            )
        )
        self.save_must_fin_socks([client])

        client.make_request(self.get_request)
        self.assertTrue(client.wait_for_headers_frame(stream_id=1))
        # Client send DATA frame with stream id 0.
        # Tempesta MUST return GOAWAY frame with PROTOCOL_ERROR
        client.send_bytes(b"\x00\x00\x03\x00\x01\x00\x00\x00\x00123")

        self.assertTrue(
            client.wait_for_connection_close(),
            "Tempesta did not close connection when sending "
            "the GOAWAY frame with a window size is 0.",
        )
        self.assertIn(
            ErrorCodes.PROTOCOL_ERROR,
            client.error_codes,
            "Tempesta did not forward the GOAWAY frame when a window size is 0.",
        )
        sniffer.stop()
        self.assert_fin_socks(sniffer.packets)

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
