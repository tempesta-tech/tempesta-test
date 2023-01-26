"""Functional tests for h2 streams."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from h2.connection import AllowedStreamIDs
from h2.errors import ErrorCodes
from h2.stream import StreamInputs

from framework import deproxy_client, tester


class TestH2Stream(tester.TempestaTest):

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        }
    ]

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    tempesta = {
        "config": """
            listen 443 proto=h2;
            server ${server_ip}:8000;
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;
        """
    }

    request_headers = [
        (":authority", "debian"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "POST"),
    ]

    def test_max_concurrent_stream(self):
        """
        An endpoint that receives a HEADERS frame that causes its advertised concurrent
        stream limit to be exceeded MUST treat this as a stream error
        of type PROTOCOL_ERROR or REFUSED_STREAM.
        RFC 9113 5.1.2
        """
        self.start_all_services()
        client = self.get_client("deproxy")

        # TODO need change after fix issue #1394
        max_streams = 128

        for _ in range(max_streams):
            client.make_request(request=self.request_headers, end_stream=False)
            client.stream_id += 2

        client.make_request(request=self.request_headers, end_stream=True)
        client.wait_for_response(1)

        self.assertIn(ErrorCodes.PROTOCOL_ERROR or ErrorCodes.REFUSED_STREAM, client.error_codes)

    def test_reuse_stream_id(self):
        """
        Stream identifiers cannot be reused.

        An endpoint that receives an unexpected stream identifier MUST
        respond with a connection error of type PROTOCOL_ERROR.
        RFC 9113 5.1.1
        """
        self.start_all_services()
        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")
        self.__initiate_h2_connection(client)

        # send headers frame with stream_id = 1
        client.send_request(self.request_headers, "200")
        # send headers frame with stream_id = 1 again.
        client.send_bytes(
            data=b"\x00\x00\n\x01\x05\x00\x00\x00\x01A\x85\x90\xb1\x98u\x7f\x84\x87\x83",
            expect_response=True,
        )
        client.wait_for_response(1)

        client.send_request(self.request_headers, "200")

        self.assertIn(ErrorCodes.PROTOCOL_ERROR, client.error_codes)

    def test_headers_frame_with_zero_stream_id(self):
        """
        The identifier of a newly established stream MUST be numerically greater
        than all streams that the initiating endpoint has opened or reserved.

        An endpoint that receives an unexpected stream identifier MUST
        respond with a connection error of type PROTOCOL_ERROR.
        RFC 9113 5.1.1
        """
        self.start_all_services()
        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")
        # add preamble + settings frame with default variable into data_to_send
        self.__initiate_h2_connection(client)
        # send headers frame with stream_id = 0.
        client.send_bytes(
            b"\x00\x00\n\x01\x05\x00\x00\x00\x00A\x85\x90\xb1\x98u\x7f\x84\x87\x83",
            expect_response=True,
        )
        client.wait_for_response(1)

        self.assertIn(ErrorCodes.PROTOCOL_ERROR, client.error_codes)

    def test_request_with_even_numbered_stream_id(self):
        """
        Streams initiated by a client MUST use odd-numbered stream identifiers.

        An endpoint that receives an unexpected stream identifier MUST
        respond with a connection error of type PROTOCOL_ERROR.
        RFC 9113 5.1.1
        """
        self.start_all_services()
        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")
        self.__initiate_h2_connection(client)
        # send headers frame with stream_id = 2.
        client.send_bytes(
            b"\x00\x00\n\x01\x05\x00\x00\x00\x02A\x85\x90\xb1\x98u\x7f\x84\x87\x83",
            expect_response=True,
        )
        client.wait_for_response(1)

        self.assertIn(ErrorCodes.PROTOCOL_ERROR, client.error_codes)

    def test_request_with_large_stream_id(self):
        """
        stream id >= 0x7fffffff (2**31-1).

        A reserved 1-bit field. The semantics of this bit are undefined,
        and the bit MUST remain unset (0x00) when sending and MUST be ignored when receiving.
        RFC 9113 4.2
        """
        self.start_all_services()
        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")
        self.__initiate_h2_connection(client)

        # Create stream that H2Connection object does not raise error.
        # We are creating stream with id = 2 ** 31 - 1 because Tempesta must return response
        # in stream with id = 2 ** 31 - 1, but request will be made in stream with id = 2 ** 32 - 1
        stream = client.h2_connection._begin_new_stream(
            (2**31 - 1), AllowedStreamIDs(client.h2_connection.config.client_side)
        )
        stream.state_machine.process_input(StreamInputs.SEND_HEADERS)
        # add request method that avoid error in handle_read
        client.methods.append("POST")
        # send headers frame with stream_id = 0xffffffff (2**32-1).
        client.send_bytes(
            b"\x00\x00\n\x01\x05\xff\xff\xff\xffA\x85\x90\xb1\x98u\x7f\x84\x87\x83",
            expect_response=True,
        )

        self.assertTrue(client.wait_for_response())
        self.assertEqual(client.last_response.status, "200")

    @staticmethod
    def __initiate_h2_connection(client: deproxy_client.DeproxyClientH2):
        # add preamble + settings frame with default variable into data_to_send
        client.update_initiate_settings()
        # send preamble + settings frame to Tempesta
        client.send_bytes(client.h2_connection.data_to_send())
        client.h2_connection.clear_outbound_data_buffer()
