"""Testing for missing or wrong body length in request."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework.deproxy.deproxy_client import DeproxyClient
from framework.helpers import checks_for_tests as checks
from framework.helpers import tf_cfg
from framework.test_suite.tester import TempestaTest
from tests.wrong_body_length.utils import TestContentLengthBase


class RequestContentLengthBase(TestContentLengthBase, base=True):
    """Base class for checking length of request body."""

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


class RequestCorrectBodyLength(RequestContentLengthBase):
    """
    Send request to server with body and correct Content-Length header.
    Check that server has received request and client has received response.
    """

    request_headers = (
        "Connection: keep-alive\r\n"
        + "Accept: */*\r\n"
        + "Content-Length: 33\r\n"
        + "Content-type: text/plain\r\n"
    )
    expected_requests_to_server = 1
    expected_response_status = "204"
    cl_msg_parsing_errors = 0

    def test_post_request(self):
        """Test for POST request method."""
        self.request_method = "POST"
        self._test()

    def test_put_request(self):
        """Test for PUT request method."""
        self.request_method = "PUT"
        self._test()


class RequestDuplicateBodyLength(RequestContentLengthBase):
    """
    Send request to server with body and duplicated Content-Length header.
    Check that server has not received request and client has received response.
    """

    request_headers = (
        "Connection: keep-alive\r\n"
        + "Accept: */*\r\n"
        + "Content-Length: 33, 33\r\n"
        + "Content-type: text/plain\r\n"
    )
    expected_requests_to_server = 0
    expected_response_status = "400"
    cl_msg_parsing_errors = 1

    def test_post_request(self):
        """Test for POST request method."""
        self.request_method = "POST"
        self._test()

    def test_put_request(self):
        """Test for PUT request method."""
        self.request_method = "PUT"
        self._test()


class RequestSecondBodyLength(RequestContentLengthBase):
    """
    Send request to server with body and two Content-Length headers.
    Check that server has not received request and client has received response.
    """

    request_headers = (
        "Connection: keep-alive\r\n"
        + "Accept: */*\r\n"
        + "Content-Length: 33\r\n"
        + "Content-type: text/plain\r\n"
        + "Content-Length: 33\r\n"
    )
    expected_requests_to_server = 0
    expected_response_status = "400"
    cl_msg_parsing_errors = 1

    def test_post_request(self):
        """Test for POST request method."""
        self.request_method = "POST"
        self._test()

    def test_put_request(self):
        """Test for PUT request method."""
        self.request_method = "PUT"
        self._test()


class RequestInvalidBodyLength(RequestContentLengthBase):
    """
    Send request to server with body and invalid Content-Length header.
    Check that server has not received request and client has received response.
    """

    request_headers = (
        "Connection: keep-alive\r\n"
        + "Accept: */*\r\n"
        + "Content-Length: invalid\r\n"
        + "Content-type: text/plain\r\n"
    )
    expected_requests_to_server = 0
    expected_response_status = "400"
    cl_msg_parsing_errors = 1

    def test_post_request(self):
        """Test for POST request method."""
        self.request_method = "POST"
        self._test()

    def test_put_request(self):
        """Test for PUT request method."""
        self.request_method = "PUT"
        self._test()


class RequestNegativeBodyLength(RequestContentLengthBase):
    """
    Send request to server with body and negative Content-Length header.
    Check that server has not received request and client has received response.
    """

    request_headers = (
        "Connection: keep-alive\r\n"
        + "Accept: */*\r\n"
        + "Content-Length: -10\r\n"
        + "Content-type: text/plain\r\n"
    )
    expected_requests_to_server = 0
    expected_response_status = "400"
    cl_msg_parsing_errors = 1

    def test_post_request(self):
        """Test for POST request method."""
        self.request_method = "POST"
        self._test()

    def test_put_request(self):
        """Test for PUT request method."""
        self.request_method = "PUT"
        self._test()


class RequestDecimalBodyLength(RequestContentLengthBase):
    """
    Send request to server with body and decimal Content-Length header.
    Check that server has not received request and client has received response.
    """

    request_headers = (
        "Connection: keep-alive\r\n"
        + "Accept: */*\r\n"
        + "Content-Length: 0.5\r\n"
        + "Content-type: text/plain\r\n"
    )
    expected_requests_to_server = 0
    expected_response_status = "400"
    cl_msg_parsing_errors = 1

    def test_post_request(self):
        """Test for POST request method."""
        self.request_method = "POST"
        self._test()

    def test_put_request(self):
        """Test for PUT request method."""
        self.request_method = "PUT"
        self._test()


class RequestMissingBodyLength(RequestContentLengthBase):
    """
    Send request to server with body and without Content-Length header.
    Check that server has not received request and client has received response.
    """

    request_headers = (
        "Connection: keep-alive\r\n" + "Accept: */*\r\n" + "Content-type: text/plain\r\n"
    )
    expected_requests_to_server = 0
    expected_response_status = "400"
    cl_msg_parsing_errors = 1

    def test_post_request(self):
        """Test for POST request method."""
        self.request_method = "POST"
        self._test()

    def test_put_request(self):
        """Test for PUT request method."""
        self.request_method = "PUT"
        self._test()


class RequestEmptyBodyLength(RequestContentLengthBase):
    """
    Send request to server with body and empty Content-Length header.
    Check that server has not received request and client has received response.
    """

    request_headers = (
        "Connection: keep-alive\r\n"
        + "Accept: */*\r\n"
        + "Content-Length: \r\n"
        + "Content-type: text/plain\r\n"
    )
    expected_requests_to_server = 0
    expected_response_status = "400"
    cl_msg_parsing_errors = 1

    def test_post_request(self):
        """Test for POST request method."""
        self.request_method = "POST"
        self._test()

    def test_put_request(self):
        """Test for PUT request method."""
        self.request_method = "PUT"
        self._test()


class RequestSmallBodyLength(RequestContentLengthBase):
    """
    Send request to server with body and smaller Content-Length header.
    Check that server has not received request and client has received response.
    """

    request_headers = (
        "Connection: keep-alive\r\n"
        + "Accept: */*\r\n"
        + "Content-Length: 10\r\n"
        + "Content-type: text/plain\r\n"
    )
    expected_requests_to_server = 1
    expected_response_status = "400"
    cl_msg_parsing_errors = 1

    def test_post_request(self):
        """Test for POST request method."""
        self.request_method = "POST"
        self._test()

    def test_put_request(self):
        """Test for PUT request method."""
        self.request_method = "PUT"
        self._test()


class RequestLongBodyLength(TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 204 No Content\r\n"
                + "Connection: keep-alive\r\n"
                + "Server: Deproxy Server\r\n"
                + "\r\n"
            ),
        },
    ]

    tempesta = {
        "config": """
            listen 80;
            frang_limits {
                http_strict_host_checking false;
                http_methods GET PUT POST;
            }
            srv_group default {
                server ${server_ip}:8000;
            }

            vhost default {
                proxy_pass default;
            }

            cache 0;
            block_action error reply;
            block_action attack reply;
            keepalive_timeout 1;
            """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    def test_post_request(self):
        self._test(method="POST")

    def test_put_request(self):
        self._test(method="PUT")

    def _test(self, method: str) -> None:
        """
        Send request with body and longer Content-length header.
        Check that Tempesta has not sent client request and closed connection after the set time
        'keepalive'.
        """
        self.start_all_services()
        client: DeproxyClient = self.get_client("deproxy")
        srv = self.get_server("deproxy")
        client.parsing = False

        client.make_request(
            f"{method} / HTTP/1.1\r\n"
            + f'Host: {tf_cfg.cfg.get("Client", "hostname")}\r\n'
            + "Connection: keep-alive\r\n"
            + "Accept: */*\r\n"
            + "Content-Length: 40\r\n"
            + "Content-type: text/plain\r\n"
            + "\r\n"
            + "body\r\n"
        )
        client.wait_for_response(timeout=3)

        self.assertIsNone(
            client.last_response,
            "Tempesta returned a response, it was expected that the connection would be closed.",
        )
        self.assertEqual(
            0,
            len(srv.requests),
            "The server received request. The expected value is 0.",
        )
        checks.check_tempesta_request_and_response_stats(
            tempesta=self.get_tempesta(),
            cl_msg_received=1,
            cl_msg_forwarded=0,
            srv_msg_received=0,
            srv_msg_forwarded=0,
        )
