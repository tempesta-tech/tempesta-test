"""Testing for missing or wrong body length in h2 request."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

from t_wrong_body_length import test_request_wrong_length as t
from t_wrong_body_length.utils import H2Config, TestContentLengthBase


class H2RequestContentLengthBase(H2Config, TestContentLengthBase, base=True):
    # request params
    uri = "/"
    request_body = "PUT / HTTP/1.1\r\nHost: localhost\r\n"

    # response params
    response_status = "204 No Content"
    response_headers = ""
    response_body = ""
    keep_alive = 0

    # expected params for check
    srv_msg_parsing_errors = 0
    cl_msg_other_errors = 0
    srv_msg_other_errors = 0

    def _test(self):
        srv = self.get_server("deproxy")
        super()._test()
        if self.expected_response_status in ["200", "204"]:
            self.assertIn("content-length", srv.last_request.headers)


class RequestCorrectBodyLength(H2RequestContentLengthBase, t.RequestCorrectBodyLength):
    request_headers = [("content-length", "33")]
    expected_response_status = "204"


class RequestMissingBodyLength(H2RequestContentLengthBase, t.RequestMissingBodyLength):
    request_headers = []
    expected_requests_to_server = 1
    expected_response_status = "204"
    cl_msg_parsing_errors = 0


class RequestDuplicateBodyLength(H2RequestContentLengthBase, t.RequestDuplicateBodyLength):
    request_headers = [("content-length", "33, 33")]


class RequestSecondBodyLength(H2RequestContentLengthBase, t.RequestSecondBodyLength):
    request_headers = [("content-length", "33"), ("content-length", "33")]


class RequestInvalidBodyLength(H2RequestContentLengthBase, t.RequestInvalidBodyLength):
    request_headers = [("content-length", "invalid")]


class RequestNegativeBodyLength(H2RequestContentLengthBase, t.RequestNegativeBodyLength):
    request_headers = [("content-length", "-10")]


class RequestDecimalBodyLength(H2RequestContentLengthBase, t.RequestDecimalBodyLength):
    request_headers = [("content-length", "0.5")]


class RequestEmptyBodyLength(H2RequestContentLengthBase, t.RequestEmptyBodyLength):
    request_headers = [("content-length", "")]


class RequestSmallBodyLength(H2RequestContentLengthBase, t.RequestSmallBodyLength):
    request_headers = [("content-length", "10")]
    expected_requests_to_server = 0
    expected_response_status = "400"
    cl_msg_parsing_errors = 1


class RequestLongBodyLength(H2RequestContentLengthBase):
    request_headers = [("content-length", "40")]
    expected_requests_to_server = 0
    expected_response_status = "400"
    cl_msg_parsing_errors = 1

    def test_post_request(self):
        self.request_method = "POST"
        self._test()

    def test_put_request(self):
        self.request_method = "PUT"
        self._test()
