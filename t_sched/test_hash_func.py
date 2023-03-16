"""
Functional test for hash scheduler. Requested URI must be pinned to specific
server connection, thus repeated request to the same URI will go to the same
server connection.
"""

from __future__ import print_function

from helpers import chains, deproxy
from testers import functional

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2018 Tempesta Technologies, Inc."
__license__ = "GPL2"


class HashSchedulerTest(functional.FunctionalTest):
    """Check that the same server connection is used for the same resource."""

    # Total number of requests
    messages = 100
    # Number of different Uris
    uri_n = 10

    def configure_tempesta(self):
        functional.FunctionalTest.configure_tempesta(self)
        for sg in self.tempesta.config.server_groups:
            sg.sched = "hash"

    def create_tester(self):
        self.tester = HashTester(self.client, self.servers)

    def create_servers(self):
        """Create more than one server for better testing."""
        self.create_servers_helper(5)

    def chains(self):
        uris = ["/resource-%d" % (i % self.uri_n) for i in range(self.messages)]
        msg_chains = [chains.base(uri=uris[i]) for i in range(self.messages)]
        return msg_chains

    def test_hash_scheduler(self):
        self.generic_test_routine("cache 0;\n", self.chains())


class HashTester(deproxy.Deproxy):
    def __init__(self, *args, **kwargs):
        deproxy.Deproxy.__init__(self, *args, **kwargs)
        self.used_connections = {}

    def run(self):
        # Run loop to setup all the connections
        self.loop(0.1)
        self.used_connections = {}
        deproxy.Deproxy.run(self)

    def received_forwarded_request(self, request, connection):
        if request.uri not in self.used_connections:
            self.used_connections[request.uri] = connection
        else:
            assert (
                self.used_connections[request.uri] is connection
            ), "URI-to-srv_conn pinning is broken in hash scheduler"
        return deproxy.Deproxy.received_forwarded_request(self, request, connection)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
