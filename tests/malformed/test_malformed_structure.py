from framework.test_suite import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"


class MalformedStructureTest(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": """HTTP/1.1 200 OK
Content-Length: 0
Connection: keep-alive

""",
        },
    ]

    tempesta = {
        "config": """

block_action attack reply;
block_action error reply;

cache 0;
server ${server_ip}:8000;

""",
    }

    clients = [
        {"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"},
    ]

    def common_check(self, request, expect="400"):
        self.start_all_services()

        client = self.get_client("deproxy")
        client.parsing = False

        client.send_request(request, expect)

    def test_lfcr(self):
        """
        \r actually don't belong to the line, where it placed.
        it belongs to the next line

        https://tools.ietf.org/html/rfc7230#section-3.5

        Although the line terminator for the start-line and header fields is
        the sequence CRLF, a recipient MAY recognize a single LF as a line
        terminator and ignore any preceding CR.

        So we have '\rHost: localhost\n' next line
        """

        request = "GET / HTTP/1.1\n\r" "Host: localhost\n\r" "\n\r"
        self.common_check(request, "400")

    def test_space(self):
        """
        https://tools.ietf.org/html/rfc7230#section-3.2.4
        No whitespace is allowed between the header field-name and colon.  In
        the past, differences in the handling of such whitespace have led to
        security vulnerabilities in request routing and response handling.  A
        server MUST reject any received request message that contains
        whitespace between a header field-name and colon with a response code
        of 400 (Bad Request).  A proxy MUST remove any such whitespace from a
        response message before forwarding the message downstream.
        """
        deproxy_cl = self.get_client("deproxy")

        self.start_all_services()

        deproxy_cl.make_request("GET / HTTP/1.1\r\nHost : localhost\r\n\r\n")
        deproxy_cl.wait_for_response(timeout=5, strict=True)
        self.assertEqual(deproxy_cl.last_response.status, "400")

    def test_crSPlf(self):
        """
        https://tools.ietf.org/html/rfc7230#section-3

        HTTP-message   = start-line
                          *( header-field CRLF )
                          CRLF
                          [ message-body ]

        https://tools.ietf.org/html/rfc7230#section-3.5

        Although the line terminator for the start-line and header fields is
        the sequence CRLF, a recipient MAY recognize a single LF as a line
        terminator and ignore any preceding CR.

        https://tools.ietf.org/html/rfc7230#section-3.2

        header-field   = field-name ":" OWS field-value OWS

        field-name     = token
        field-value    = *( field-content / obs-fold )
        field-content  = field-vchar [ 1*( SP / HTAB ) field-vchar ]

        We have content = 'localhost\r', which is invalid, because
        \r is neither a VCHAR nor obs-text
        """
        request = "GET / HTTP/1.1\r\n" "Host: localhost\r \n" "\r\n"
        self.common_check(request, "400")
