"""
Set of tests to verify HTTP rules processing correctness (in one HTTP chain).
"""

from __future__ import print_function
import asyncore
from helpers import tempesta, deproxy, tf_cfg, chains, control
from testers import functional

import unittest

class HttpRules(functional.FunctionalTest):
    """All requests must be forwarded to the right vhosts and
    server groups according to rule in http_chain.
    """

    requests_n = 20

    config = (
        'cache 0;\n'
        '\n'
        'http_chain {\n'
        '  uri == "/static*" -> uri_p;\n'
        '  uri == "*.php" -> uri_s;\n'
        '  host == "static.*" -> host_p;\n'
        '  host == "*tempesta-tech.com" -> host_s;\n'
        '  host == "foo.example.com" -> host_e;\n'
        '  hdr Host == "bar.*" -> hdr_h_p;\n'
        '  hdr host == "buzz.natsys-lab.com" -> hdr_h_e;\n'
        '  hdr Host == "*natsys-lab.com" -> hdr_h_s;\n'
        '  hdr Referer ==  "example.com" -> hdr_r_e;\n'
        '  hdr Referer ==  "*.com" -> hdr_r_s;\n'
        '  hdr referer ==  "http://example.com*" -> hdr_r_p;\n'
        '  hdr From ==  "testuser@example.com" -> hdr_raw_e;\n'
        '  hdr Warning ==  "172 *" -> hdr_raw_p;\n'
        '  -> default;\n'
        '}\n'
        '\n')

    def make_chains(self, uri, extra_header=(None, None)):
        chain = chains.base(uri=uri)

        header, value = extra_header
        if not header is None:
            for req in [chain.request, chain.fwd_request]:
                req.headers.delete_all(header)
                req.headers.add(header, value)
                req.update()

        return [chain for _ in range(self.requests_n)]

    def create_client(self):
        # Client will be created for every server.
        for server in self.servers:
            server.client = deproxy.Client()

    def create_servers(self):
        port = tempesta.upstream_port_start_from()
        server_options = [
            (('uri_p'), ('/static/index.html'), None, None),
            (('uri_s'), ('/script.php'), None, None),
            (('host_p'), ('/'), ('host'), ('static.example.com')),
            (('host_s'), ('/'), ('host'), ('s.tempesta-tech.com')),
            (('host_e'), ('/'), ('host'), ('foo.example.com')),
            (('hdr_h_p'), ('/'), ('host'), ('bar.example.com')),
            (('hdr_h_s'), ('/'), ('host'), ('test.natsys-lab.com')),
            (('hdr_h_e'), ('/'), ('host'), ('buzz.natsys-lab.com')),
            (('hdr_r_e'), ('/'), ('referer'), ('example.com')),
            (('hdr_r_s'), ('/'), ('referer'), ('http://example.com')),
            (('hdr_r_p'), ('/'), ('referer'),
             ('http://example.com/cgi-bin/show.pl')),
            (('hdr_raw_e'), ('/'), ('from'), ('testuser@example.com')),
            (('hdr_raw_p'), ('/'), ('warning'), ('172 misc warning')),
            (('default'), ('/'), None, None)]

        for group, uri, header, value in server_options:
            # Dont need too many connections here.
            server = deproxy.Server(port=port, conns_n=1)
            port += 1
            server.group = group
            server.chains = self.make_chains(uri=uri,
                                             extra_header=(header, value))
            self.servers.append(server)

    def configure_tempesta(self):
        """ Add every server to it's own server group with default scheduler.
        """
        for s in self.servers:
            sg = tempesta.ServerGroup(s.group)
            sg.add_server(s.ip, s.port, s.conns_n)
            self.tempesta.config.add_sg(sg)

    def create_tester(self):
        self.testers = []
        for server in self.servers:
            tester = HttpSchedTester(server.client, [server])
            tester.response_cb = self.response_received
            tester.message_chains = server.chains
            self.testers.append(tester)

    def routine(self):
        for i in range(self.requests_n):
            self.responses_received = 0
            for tester in self.testers:
                tester.configure(i)
            # Run asyncore loop with default timeout
            self.testers[0].loop()
            for tester in self.testers:
                tester.check_expectations()

    def init(self):
        self.tempesta.config.set_defconfig(self.config)

        self.configure_tempesta()
        for server in self.servers:
            server.start()

        self.tempesta.start()
        for server in self.servers:
            server.client.start()

        for tester in self.testers:
            tester.start()

    def test_scheduler(self):
        self.init()
        self.routine()

        self.tempesta.get_stats()
        self.assert_tempesta()

    def response_received(self):
        self.responses_received += 1
        if self.responses_received == len(self.servers):
            raise asyncore.ExitNow

    def setUp(self):
        self.testers = []
        functional.FunctionalTest.setUp(self)

    def tearDown(self):

        if self.tempesta:
            self.tempesta.stop()
        for tester in self.testers:
            tester.stop()
        for server in self.servers:
            server.client.stop("Deproxy client")
        for server in self.servers:
            server.stop("Deproxy server")


class HttpRulesBackupServers(HttpRules):

    config = (
        'cache 0;\n'
        '\n'
        'vhost host {\n'
        '\tproxy_pass primary backup=backup;\n'
        '}\n'
        'http_chain {\n'
        '\t-> host;\n'
        '}\n'
        '\n')

    def create_tempesta(self):
        self.tempesta = control.Tempesta(vhost_auto=False)

    def make_chains(self, empty=True):
        chain = None
        if empty:
            chain = deproxy.MessageChain.empty()
        else:
            chain = chains.base()
        return [chain for _ in range(self.requests_n)]

    def create_tempesta(self):
        """ Disable vhosts auto configuration mode.
        """
        functional.FunctionalTest.create_tempesta(self)
        self.tempesta.config.vhost_auto_mode = False

    def create_server_helper(self, group, port):
        server = deproxy.Server(port=port, conns_n=1)
        server.group = group
        server.chains = self.make_chains()
        return server

    def create_servers(self):
        port = tempesta.upstream_port_start_from()
        self.main_server = self.create_server_helper('primary', port)
        self.backup_server = self.create_server_helper('backup', port + 1)
        self.servers.append(self.main_server)
        self.servers.append(self.backup_server)

    def test_scheduler(self):
        self.init()
        # Main server is online, backup server must not receive traffic.
        self.main_server.tester.message_chains = (
            self.make_chains(empty=False))
        self.backup_server.tester.message_chains = (
            self.make_chains(empty=True))
        self.routine()

        # Shutdown main server, responses must be forwarded to backup.
        self.main_server.tester.client.stop()
        self.main_server.stop()
        self.main_server.tester.message_chains = (
            self.make_chains(empty=True))

        self.backup_server.tester.message_chains = (
            self.make_chains(empty=False))
        self.routine()

        # Return main server back operational.
        self.testers.remove(self.main_server.tester)
        self.main_server = self.create_server_helper(
            group=self.main_server.group, port=self.main_server.port)
        tester = HttpSchedTester(deproxy.Client(), [self.main_server])
        tester.response_cb = self.response_received
        self.testers.append(tester)

        self.main_server.tester.message_chains = (
            self.make_chains(empty=False))
        self.backup_server.tester.message_chains = (
            self.make_chains(empty=True))

        self.main_server.start()
        self.main_server.tester.client.start()
        self.routine()

        # Check tempesta for no errors
        self.tempesta.get_stats()
        self.assert_tempesta()

    def response_received(self):
        self.responses_received += 1
        if self.responses_received == 1:
            raise asyncore.ExitNow


class HttpSchedTester(deproxy.Deproxy):

    def __init__(self, *args, **kwargs):
        deproxy.Deproxy.__init__(self, *args, **kwargs)

    def configure(self, chain_n):
        if chain_n in range(len(self.message_chains)):
            self.current_chain = self.message_chains[chain_n]
        else:
            self.current_chain = deproxy.MessageChain.empty()

        self.received_chain = deproxy.MessageChain.empty()
        self.client.clear()
        self.client.set_request(self.current_chain)

    def received_response(self, response):
        # A lot of clients running, dont raise asyncore.ExitNow directly
        # instead call the
        self.received_chain.response = response
        self.response_cb()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
