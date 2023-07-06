from framework import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2021-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"


class MalformedCrlfTest(tester.TempestaTest):
    """
    RFC 7230: https://datatracker.ietf.org/doc/html/rfc7230#section-3.5
       | In the interest of robustness, a server that is expecting to receive
       | and parse a request-line SHOULD ignore at least one empty line (CRLF)
       | received prior to the request-line.
       |
       | Although the line terminator for the start-line and header fields is
       | the sequence CRLF, a recipient MAY recognize a single LF as a line
       | terminator and ignore any preceding CR.

    Tempesta honours the requirement.
    But messages containing more preceding CRLFs (or LFs) must be blocked and
    must not be forewrded to backend.

    This function is required by issue #1061 and submitted in pull request
    1534

    The plan for functional tests is:
    * a single request with many CRLFs is blocked
    * a single request with one CRLF or just LF is passed and both the CRLF
      or LF are not presented in forwarded request
    * a pipelined request after another request with many CRLFs is blocked
    * a pipelined request after another request with one CRLF or just LF is
      passed and both the CRLF or LF are not presented in forwarded request
    """

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "keep_original_data": True,
            "response": "static",
            "response_content": """HTTP/1.1 200 OK
Content-Length: 0
Connection: keep-alive

""",
        },
    ]

    tempesta = {
        "config": """
cache 0;
server ${general_ip}:8000 conns_n=1;

""",
    }

    clients = [
        {"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"},
    ]

    def common_check(self, request, expect_status=200, expect=""):
        """
        Set expect to expected proxied request, to empty string to skip request
        check and to None to check that request is missing.
        """
        deproxy_srv = self.get_server("deproxy")
        deproxy_srv.conns_n = 1
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.parsing = False

        self.start_all_services()

        deproxy_cl.make_requests(request, True)

        if isinstance(request, list):
            deproxy_cl.valid_req_num = 2

        self.assertTrue(deproxy_cl.wait_for_response(timeout=5), "Response not received")

        status = int(deproxy_cl.last_response.status)
        self.assertTrue(
            status == expect_status, f"Wrong status: {status}, expected: {expect_status}"
        )
        if expect is None:
            self.assertTrue(
                deproxy_srv.last_request is None, "Request was unexpectedly sent to backend"
            )
        elif expect:
            self.assertIn(
                deproxy_srv.last_request.uri,
                expect,
                "Request sent to backend differs from expected one",
            )
        self.assertFalse(deproxy_cl.connection_is_closed())

    def test_02_no_crlf_pipeline(self):
        """Test 2 normal requests in pipeline."""
        request = [
            "GET /aaa HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "GET /bbb HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
        ]
        expect = "GET /bbb HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        self.common_check(request, 200, expect)

    def test_03_single_crlf(self):
        """
        Test single CRLF before request
        Request should be passed to backed with stripped CRLF
        Proxy should return positive response
        """
        request = "\r\n" "GET / HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        expect = "GET / HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        self.common_check(request, 200, expect)

    def test_04_single_crlf_pipeline(self):
        """
        Test single CRLF before 2nd request in a pipeline
        Request should be passed to the backend with stripped CRLF
        Proxy should return positive response
        """
        request = [
            "GET /aaa HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "\r\n" "GET /bbb HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
        ]
        expect = "GET /bbb HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        self.common_check(request, 200, expect)

    def test_05_single_lf(self):
        """
        Test single LF before request
        Request should be passed to backed with stripped LF
        Proxy should return positive response
        """
        request = "\n" "GET / HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        expect = "GET / HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        self.common_check(request, 200, expect)

    def test_06_single_lf_pipeline(self):
        """
        Test single LF before 2nd request in a pipeline
        Request should be passed to backed with stripped LF
        Proxy should return positive response
        """
        request = [
            "GET /aaa HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "\n" "GET /bbb HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
        ]
        expect = "GET /bbb HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        self.common_check(request, 200, expect)

    def test_07_double_crlf(self):
        """
        Test double CRLF before request
        Request should be rejected by the proxy
        """
        request = "\r\n" "\r\n" "GET / HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        expect = None
        self.common_check(request, 400, expect)

    def test_08_double_crlf_pipeline(self):
        """
        Test double CRLF before 2nd request in a pipeline
        The 1st request should be passed to backend
        The 2nd request should be rejected by the proxy
        """
        request = [
            "GET /aaa HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "\r\n" "\r\n" "GET /bbb HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
        ]
        expect = "GET /aaa HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        self.common_check(request, 400, expect)

    def test_09_double_lf(self):
        """
        Test double LF before request
        Request should be rejected by the proxy
        """
        request = "\n" "\n" "GET / HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        expect = None
        self.common_check(request, 400, expect)

    def test_10_double_lf_pipeline(self):
        """
        Test double LF before 2nd request in a pipeline
        The 1st request should be sent to backed
        The 2nd request should be rejected by the proxy
        """
        request = [
            "GET /aaa HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n" "\n" "\n",
            "GET /bbb HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
        ]
        expect = "GET /aaa HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        self.common_check(request, 400, expect)
