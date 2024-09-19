"""
Tests for TCP connection closing.
"""

from __future__ import print_function

import asyncore

from framework.tester import TempestaTest
from helpers import analyzer, chains, deproxy, remote
from testers import functional

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017 Tempesta Technologies, Inc."
__license__ = "GPL2"


class CloseConnection(TempestaTest):
    """Regular connection closing."""

    clients = [
        {
            "id": "deproxy-1",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    tempesta = {
        "config": """
cache 0;
listen 80;
server ${server_ip}:8001;
tls_match_any_server_name;
block_action attack reply;
block_action error reply;
    """
    }

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        },
    ]

    def stop_and_close(self):
        """To check the correctness of connection closing - we need to close
        it before stopping sniffer and analyzing sniffer's output (and throwing
        an exception in case of failure); so, we need to close Deproxy client
        and server connections in test_* function (not in tearDown).
        """
        asyncore.close_all()
        self.client.stop()  # TODO here client is DeproxyClient
        self.tempesta.stop()  # TODO here tempesta is control.Tempesta()
        self.tester.stop()

    def create_sniffer(self):
        self.sniffer = analyzer.AnalyzerCloseRegular(
            remote.tempesta,  # TODO node
            # self.tempesta.node,
            "Tempesta",  # TODO host
            # self.tempesta.host,
            node_close=False,
            timeout=10,
        )

    def assert_results(self):
        self.assertTrue(self.sniffer.check_results(), msg="Incorrect FIN-ACK sequence detected.")

    def create_chains(self):
        return [chains.base(forward=True)]

    def run_sniffer(self):
        self.sniffer.start()
        # self.generic_test_routine("cache 0;\n", self.create_chains())
        # self.stop_and_close()
        self.sniffer.stop()

    def test(self):

        ## TODO new

        self.create_sniffer()
        self.sniffer.start()

        self.start_all_services()
        client = self.get_client("deproxy-1")
        client.start()
        client.send_request(f"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", "200")
        client.stop()

        # self.cleanup_deproxy()

        tempesta = self.get_tempesta()
        tempesta.stop()

        self.sniffer.stop()

        self.assert_results()

        ## TODO new ends

        # self.create_sniffer()
        # self.run_sniffer()
        # self.assert_results()


class CloseClientConnectiononInvalidReq(CloseConnection):
    """When an invalid request is received by Tempesta, it responds with 400
    and closes client connection.
    """

    def assert_tempesta(self):
        pass

    def create_chains(self):
        chain_200 = chains.base(forward=True)
        # Append some garbge to message.
        chain_200.request.msg += "".join(["Arbitrary data " for _ in range(300)])
        # Body is not declared in the request, so the garbage will be treated
        # as a new request. 400 response will be sent and client connection
        # will be closed.
        chain_400 = deproxy.MessageChain(
            request=deproxy.Request(), expected_response=chains.response_400()
        )
        return [chain_200, chain_400]

    def create_sniffer(self):
        self.sniffer = analyzer.AnalyzerCloseRegular(
            self.tempesta.node, self.tempesta.host, timeout=10
        )


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
