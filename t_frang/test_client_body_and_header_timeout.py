"""Functional tests for `client_body_timeout` and `client_header_timeout` in Tempesta config."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

import time

from t_frang.frang_test_case import FrangTestCase

TIMEOUT = 1


class TestTimeoutBase(FrangTestCase):
    request_segment_1: str
    request_segment_2: str
    error: str
    frang_config: str

    def send_request_with_sleep(self, sleep: float):
        client = self.get_client("deproxy-1")
        client.parsing = False
        client.start()

        client.make_request(self.request_segment_1)
        if sleep < TIMEOUT:
            time.sleep(sleep)
            client.make_request(self.request_segment_2)
            client.valid_req_num = 1
        client.wait_for_response(sleep + 1)


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
        self.check_response(self.get_client("deproxy-1"), "200", self.error)

    def test_timeout_invalid(self):
        self.set_frang_config(frang_config=self.frang_config)
        self.send_request_with_sleep(sleep=TIMEOUT * 1.5)
        self.check_response(self.get_client("deproxy-1"), "403", self.error)


class ClientHeaderTimeout(ClientBodyTimeout):
    request_segment_1 = "POST / HTTP/1.1\r\nHost: debian\r\n"
    request_segment_2 = "Content-Type: text/html\r\nContent-Length: 0\r\n\r\n"
    error = "Warning: frang: client header timeout exceeded"
    frang_config = f"client_header_timeout {TIMEOUT};"
