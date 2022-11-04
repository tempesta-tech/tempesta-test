__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2018 Tempesta Technologies, Inc."
__license__ = "GPL2"

import asyncore

from helpers import deproxy, tf_cfg


class ClientMultipleResponses(deproxy.Client):
    """Client with support of parsing multiple responses"""

    method = "INVALID"
    request_buffer = ""

    def set_request(self, request_chain):
        if request_chain != None:
            self.method = request_chain.method
            self.request_buffer = request_chain.request.msg

    def handle_read(self):
        self.response_buffer += self.recv(deproxy.MAX_MESSAGE_SIZE).decode()
        if not self.response_buffer:
            return
        tf_cfg.dbg(4, "\tDeproxy: Client: Receive response from Tempesta.")
        tf_cfg.dbg(5, self.response_buffer)

        method = self.method
        while len(self.response_buffer) > 0:
            try:
                response = deproxy.Response(self.response_buffer, method=method)
                self.response_buffer = self.response_buffer[len(response.msg) :]
                method = "GET"
            except deproxy.ParseError:
                tf_cfg.dbg(
                    4,
                    (
                        "Deproxy: Client: Can't parse message\n"
                        "<<<<<\n%s>>>>>" % self.response_buffer
                    ),
                )
                raise
            if self.tester:
                self.tester.received_response(response)

        self.response_buffer = ""
        raise asyncore.ExitNow


class BadLengthMessageChain(deproxy.MessageChain):
    def __init__(self, request, expected_responses, forwarded_request=None, server_response=None):
        deproxy.MessageChain.__init__(
            self,
            request=request,
            forwarded_request=forwarded_request,
            server_response=server_response,
            expected_response=None,
        )
        self.responses = expected_responses
        self.method = request.method

    @staticmethod
    def empty():
        return BadLengthMessageChain(deproxy.Request(), [])


class BadLengthDeproxy(deproxy.Deproxy):
    """Support of invalid length"""

    def __compare_messages(self, expected, received, message):
        expected.set_expected(expected_time_delta=self.timeout)
        assert expected == received, (
            "Received message (%s) does not suit expected one!\n\n"
            "\tReceieved:\n<<<<<|\n%s|>>>>>\n"
            "\tExpected:\n<<<<<|\n%s|>>>>>\n" % (message, received.msg, expected.msg)
        )

    def run(self):
        for self.current_chain in self.message_chains:
            self.received_chain = BadLengthMessageChain.empty()
            self.client.clear()
            self.client.set_request(self.current_chain)
            self.loop()
            self.check_expectations()

    def check_expectations(self):
        self.__compare_messages(
            self.current_chain.fwd_request, self.received_chain.fwd_request, "fwd_request"
        )
        nexpected = len(self.current_chain.responses)
        nreceived = len(self.received_chain.responses)
        assert nexpected == nreceived, "Expected %i responses, but received %i" % (
            nexpected,
            nreceived,
        )
        for i in range(nexpected):
            expected = self.current_chain.responses[i]
            received = self.received_chain.responses[i]
            self.__compare_messages(expected, received, "response[%i]" % i)

    def received_response(self, response):
        """Client received response for its request."""
        self.received_chain.responses.append(response)
