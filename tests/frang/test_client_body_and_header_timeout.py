"""Functional tests for `client_body_timeout` and `client_header_timeout` in Tempesta config."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import time

from hyperframe.frame import ContinuationFrame, HeadersFrame

from tests.frang.frang_test_case import FrangTestCase, H2Config

TIMEOUT = 1


class TestTimeoutBase(FrangTestCase):
    request_segment_1: str or list
    request_segment_2: str or list
    error: str
    frang_config: str

    def send_request_with_sleep(self, sleep: float):
        self.disable_deproxy_auto_parser()
        client = self.get_client("deproxy-1")
        client.parsing = False
        client.start()

        client.make_request(request=self.request_segment_1, end_stream=False)
        time.sleep(sleep)
        client.make_request(self.request_segment_2)
        client.valid_req_num = 1
        self.assertTrue(client.wait_for_response())


class ClientBodyTimeout(TestTimeoutBase):
    request_segment_1 = (
        "POST / HTTP/1.1\r\n"
        "Host: debian\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "te"
    )
    request_segment_2 = "sts"
    error = "Warning: frang: client body timeout exceeded"
    frang_config = f"client_body_timeout {TIMEOUT};"

    def test_timeout_ok(self):
        self.set_frang_config(frang_config=self.frang_config)
        self.send_request_with_sleep(sleep=TIMEOUT / 2)
        self.check_last_response(self.get_client("deproxy-1"), "200", self.error)

    def test_timeout_invalid(self):
        self.set_frang_config(frang_config=self.frang_config)
        self.send_request_with_sleep(sleep=TIMEOUT * 1.5)

        self.check_last_response(self.get_client("deproxy-1"), "403", self.error)


class ClientHeaderTimeout(ClientBodyTimeout):
    request_segment_1 = "POST / HTTP/1.1\r\nHost: debian\r\n"
    request_segment_2 = "Content-Type: text/html\r\nContent-Length: 0\r\n\r\n"
    error = "Warning: frang: client header timeout exceeded"
    frang_config = f"client_header_timeout {TIMEOUT};"


class ClientBodyTimeoutH2(H2Config, ClientBodyTimeout):
    request_segment_1 = (
        [
            (":authority", "example.com"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "POST"),
        ],
        "request ",
    )

    request_segment_2 = "body."


class ClientHeaderTimeoutH2(H2Config, ClientHeaderTimeout):
    request_segment_1 = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "POST"),
    ]

    request_segment_2 = [("header", "header_value")]

    @staticmethod
    def __setup_connection(client):
        client.update_initial_settings()
        client.send_bytes(client.h2_connection.data_to_send())

    def send_request_with_sleep(self, sleep: float, timeout_before_send=False):
        self.disable_deproxy_auto_parser()
        client = self.get_client("deproxy-1")
        client.start()
        client.parsing = False

        self.__setup_connection(client)

        # timeout counter is created for each stream.
        client.send_request(self.get_request, "200")

        stream = client.init_stream_for_send(client.stream_id)
        header_frame = HeadersFrame(
            client.stream_id,
            client.h2_connection.encoder.encode(self.request_segment_1),
            flags={"END_STREAM"},
        )

        cont_frame = ContinuationFrame(
            client.stream_id,
            client.h2_connection.encoder.encode(self.request_segment_2),
            flags={"END_HEADERS"},
        )

        # sleep after TLS handshake and exchange SETTINGS frame
        if timeout_before_send:
            time.sleep(TIMEOUT + 1)

        client.send_bytes(header_frame.serialize())
        time.sleep(sleep)
        client.send_bytes(cont_frame.serialize())

        client.valid_req_num += 1
        client.wait_for_response(strict=True)

    def test_starting_timeout_counter(self):
        """
        Timeout counter starts when first header in current stream is received.
        """
        self.set_frang_config(frang_config=self.frang_config)
        self.send_request_with_sleep(sleep=TIMEOUT / 2, timeout_before_send=True)
        self.check_last_response(self.get_client("deproxy-1"), "200", self.error)
