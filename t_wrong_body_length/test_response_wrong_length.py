"""Testing for missing or wrong body length in response."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

from t_wrong_body_length.utils import TestContentLengthBase


class ResponseContentLengthBase(TestContentLengthBase, base=True):
    """Base class for checking length of response body."""

    request_method = "GET"
    uri = "/"
    request_headers = "Connection: keep-alive\r\n" + "Accept: */*\r\n"
    request_body = ""

    expected_body_length: int
    cl_msg_parsing_errors = 0
    cl_msg_other_errors = 0
    expected_requests_to_server = 1

    def test(self):
        """Call test from base class"""
        self._test()
        response = self.get_client("deproxy").last_response
        self.assertEqual(
            self.expected_body_length,
            len(response.body),
            "Tempesta forwarded body of unexpected length.",
        )
        self.assertEqual(
            self.expected_body_length,
            int(response.headers["content-length"]),
        )


class ResponseCorrectBodyLength(ResponseContentLengthBase):
    """
    Send request to server. Wait for the server response.
    Check that Tempesta has forwarded server response with body and correct Content-Length header.
    """

    response_status = "200 OK"
    response_body = "text"
    response_headers = (
        f"Content-length: {len(response_body)}\r\n"
        + "Content-type: text/html\r\n"
        + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
    )
    keep_alive = None
    expected_response_status = "200"
    expected_body_length = len(response_body)
    srv_msg_other_errors = 0
    srv_msg_parsing_errors = 0


class ResponseCorrectEmptyBodyLength(ResponseContentLengthBase):
    """
    Send request to server. Wait for the server response.
    Check that Tempesta has forwarded server response without body and correct Content-Length header
    """

    response_status = "200 OK"
    response_body = ""
    response_headers = (
        f"Content-length: {len(response_body)}\r\n"
        + "Content-type: text/html\r\n"
        + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
    )
    keep_alive = None
    expected_response_status = "200"
    expected_body_length = len(response_body)
    srv_msg_other_errors = 0
    srv_msg_parsing_errors = 0


class ResponseMissingEmptyBodyLength(ResponseContentLengthBase):
    """
    Send request to server. Wait for the server response.
    Check that Tempesta has forwarded server response without body and without Content-Length
    header.
    """

    response_status = "200 OK"
    response_body = "12345"
    response_headers = (
        "Content-type: text/html\r\n" + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
    )
    keep_alive = 1
    expected_response_status = "200"
    expected_body_length = len(response_body)
    srv_msg_other_errors = 0
    srv_msg_parsing_errors = 0


class ResponseSmallBodyLength(ResponseContentLengthBase):
    """
    Send request to server. Wait for the server response.
    Check that Tempesta has forwarded server response with body and smaller Content-Length
    header.
    """

    response_status = "200 OK"
    response_body = "text"
    response_headers = (
        f"Content-length: {len(response_body) - 1}\r\n"
        + "Content-type: text/html\r\n"
        + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
    )
    keep_alive = None
    expected_response_status = "200"
    expected_body_length = len(response_body) - 1
    srv_msg_other_errors = 1
    srv_msg_parsing_errors = 0


class ResponseForbiddenBodyLength(ResponseContentLengthBase):
    """
    Send request to server. Wait for the server response.
    Check that Tempesta has not forwarded 204 server response without body and zero Content-Length
    header.
    """

    response_status = "204 No Content"
    response_body = ""
    response_headers = (
        "Content-length: 0\r\n"
        + "Content-type: text/html\r\n"
        + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
    )
    keep_alive = None
    expected_response_status = "502"
    expected_body_length = len(response_body)
    srv_msg_other_errors = 0
    srv_msg_parsing_errors = 1


class ResponseSecondBodyLength(ResponseContentLengthBase):
    """
    Send request to server. Wait for the server response.
    Check that Tempesta has not forwarded server response with body and two
    Content-Length header.
    """

    response_status = "200 OK"
    response_body = "text"
    response_headers = (
        f"Content-length: {len(response_body)}\r\n"
        + "Content-type: text/html\r\n"
        + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
        + f"Content-length: {len(response_body)}\r\n"
    )
    keep_alive = None
    expected_response_status = "502"
    expected_body_length = 0
    srv_msg_other_errors = 0
    srv_msg_parsing_errors = 1


class ResponseDuplicateBodyLength(ResponseContentLengthBase):
    """
    Send request to server. Wait for the server response.
    Check that Tempesta has not forwarded server response with body and duplicate
    Content-Length header.
    """

    response_status = "200 OK"
    response_body = "text"
    response_headers = (
        f"Content-length: {len(response_body)}, {len(response_body)}\r\n"
        + "Content-type: text/html\r\n"
        + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
    )
    keep_alive = None
    expected_response_status = "502"
    expected_body_length = 0
    srv_msg_other_errors = 0
    srv_msg_parsing_errors = 1


class ResponseInvalidBodyLength(ResponseContentLengthBase):
    """
    Send request to server. Wait for the server response.
    Check that Tempesta has not forwarded server response with body and invalid
    Content-Length header.
    """

    response_status = "200 OK"
    response_body = "text"
    response_headers = (
        "Content-length: invalid\r\n"
        + "Content-type: text/html\r\n"
        + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
    )
    keep_alive = None
    expected_response_status = "502"
    expected_body_length = 0
    srv_msg_other_errors = 0
    srv_msg_parsing_errors = 1


class ResponseDecimalBodyLength(ResponseContentLengthBase):
    """
    Send request to server. Wait for the server response.
    Check that Tempesta has not forwarded server response with body and decimal
    Content-Length header.
    """

    response_status = "200 OK"
    response_body = "text"
    response_headers = (
        "Content-length: 0.5\r\n"
        + "Content-type: text/html\r\n"
        + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
    )
    keep_alive = None
    expected_response_status = "502"
    expected_body_length = 0
    srv_msg_other_errors = 0
    srv_msg_parsing_errors = 1


class ResponseNegativeBodyLength(ResponseContentLengthBase):
    """
    Send request to server. Wait for the server response.
    Check that Tempesta has not forwarded server response with body and negative
    Content-Length header.
    """

    response_status = "200 OK"
    response_body = "text"
    response_headers = (
        f"Content-length: -{len(response_body)}\r\n"
        + "Content-type: text/html\r\n"
        + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
    )
    keep_alive = None
    expected_response_status = "502"
    expected_body_length = 0
    srv_msg_other_errors = 0
    srv_msg_parsing_errors = 1


class ResponseEmptyBodyLength(ResponseContentLengthBase):
    """
    Send request to server. Wait for the server response.
    Check that Tempesta has not forwarded server response with body and empty
    Content-Length header.
    """

    response_status = "200 OK"
    response_body = "text"
    response_headers = (
        "Content-length: \r\n"
        + "Content-type: text/html\r\n"
        + "Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n"
    )
    keep_alive = None
    expected_response_status = "502"
    expected_body_length = 0
    srv_msg_other_errors = 0
    srv_msg_parsing_errors = 1
