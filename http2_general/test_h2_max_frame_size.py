__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import deproxy_client, deproxy_server
from http2_general.helpers import H2Base


class TestMaxFrameSize(H2Base, no_reload=True):
    def test_large_data_frame_in_response(self):
        """
        Tempesta must separate response body because it is larger than SETTINGS_MAX_FRAME_SIZE.
        Client must receive several DATA frames.
        """
        self.start_all_services()
        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")
        server: deproxy_server.StaticDeproxyServer = self.get_server("deproxy")

        client.update_initial_settings(max_frame_size=16384)

        response_body = "x" * 20000
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            "Date: test\r\n"
            "Server: deproxy\r\n"
            f"Content-Length: {len(response_body)}\r\n\r\n" + response_body
        )

        # H2Connection has SETTINGS_MAX_FRAME_SIZE = 16384 in local config therefore,
        # client does not receive response if Tempesta send DATA frame larger than 16384
        client.send_request(self.get_request, "200")
        self.assertEqual(len(client.last_response.body), len(response_body))

    def test_large_headers_frame_in_response(self):
        """
        Tempesta must separate response headers to HEADERS and CONTINUATION frames because
        it is larger than SETTINGS_MAX_FRAME_SIZE.
        """
        self.start_all_services()
        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")
        server: deproxy_server.StaticDeproxyServer = self.get_server("deproxy")

        client.update_initial_settings(max_frame_size=16384)

        large_header = ("qwerty", "x" * 17000)
        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            "Date: test\r\n"
            "Server: deproxy\r\n"
            f"{large_header[0]}: {large_header[1]}\r\n"
            "Content-Length: 0\r\n\r\n"
        )

        # H2Connection has SETTINGS_MAX_FRAME_SIZE = 16384 in local config therefore,
        # client does not receive response if Tempesta send HEADERS frame larger than 16384
        client.send_request(self.post_request, "200")
        self.assertIsNotNone(client.last_response.headers.get(large_header[0]))
        self.assertEqual(
            len(client.last_response.headers.get(large_header[0])), len(large_header[1])
        )

    def test_headers_frame_is_large_than_max_frame_size(self):
        """
        An endpoint MUST send an error code of FRAME_SIZE_ERROR if
        a frame exceeds the size defined in SETTINGS_MAX_FRAME_SIZE.
        RFC 9113 4.2
        """
        self.start_all_services()

        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")

        client.update_initial_settings()
        # We set SETTINGS_MAX_FRAME_SIZE = 20000 that H2Connection does not raise error,
        # but Tempesta has default SETTINGS_MAX_FRAME_SIZE = 16384.
        client.h2_connection.max_outbound_frame_size = 20000

        request = self.post_request
        request.append(("qwerty", "x" * 17000))

        client.make_request(request=request, end_stream=True, huffman=False)
        self.assertTrue(client.wait_for_connection_close())

    def test_data_frame_is_large_than_max_frame_size(self):
        """
        An endpoint MUST send an error code of FRAME_SIZE_ERROR if
        a frame exceeds the size defined in SETTINGS_MAX_FRAME_SIZE.
        RFC 9113 4.2
        """
        self.start_all_services()

        client: deproxy_client.DeproxyClientH2 = self.get_client("deproxy")

        client.update_initial_settings()
        # We set SETTINGS_MAX_FRAME_SIZE = 20000 that H2Connection does not raise error,
        # but Tempesta has default SETTINGS_MAX_FRAME_SIZE = 16384.
        client.h2_connection.max_outbound_frame_size = 20000

        client.make_request(
            request=(self.post_request, "x" * 18000), end_stream=True, huffman=False
        )
        self.assertTrue(client.wait_for_connection_close())
