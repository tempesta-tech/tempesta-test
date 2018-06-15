"""
Set of tests to verify correctness of requests redirection via HTTP tables.
Mark rules and match rules are tested here (in separate tests).
"""
from helpers import chains, remote
from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class HttpTablesTest(tester.TempestaTest):

    tempesta = {
        'config' :
        """
        srv_group grp1 {
        server ${server_ip}:8000;
        }
        srv_group grp2 {
        server ${server_ip}:8001;
        }
        srv_group grp3 {
        server ${server_ip}:8002;
        }
        srv_group grp4 {
        server ${server_ip}:8003;
        }
        srv_group grp5 {
        server ${server_ip}:8004;
        }
        srv_group grp6 {
        server ${server_ip}:8005;
        }
        srv_group grp7 {
        server ${server_ip}:8006;
        }
        vhost vh1 {
        proxy_pass grp1;
        }
        vhost vh2 {
        proxy_pass grp2;
        }
        vhost vh3 {
        proxy_pass grp3;
        }
        vhost vh4 {
        proxy_pass grp4;
        }
        vhost vh5 {
        proxy_pass grp5;
        }
        vhost vh6 {
        proxy_pass grp6;
        }
        vhost vh7 {
        proxy_pass grp7;
        }
        http_chain chain1 {
        uri == "/static*" -> vh1;
        uri == "*.php" -> vh2;
        }
        http_chain chain2 {
        uri == "/foo/*" -> vh3;
        uri == "*.html" -> vh4;
        }
        http_chain chain3 {
        uri != "*hacked.com" -> chain1;
        ->block;
        }
        http_chain {
        hdr_host == "test.app.com" -> chain2;
        hdr_uagent == "Mozilla*" -> chain2;
        hdr_ref == "*.com" -> chain1;
        hdr_ref == "http://example.*" -> chain3;
        hdr_host == "bad.host.com" -> block;
        hdr_host == "bar*" -> vh5;
        mark == 1 -> vh7;
        mark == 2 -> vh6;
        mark == 3 -> vh5;
        mark == 4 -> vh4;
        mark == 5 -> vh3;
        mark == 6 -> vh2;
        mark == 7 -> vh1;
        }
        """
    }

    clients = [
        {
            'id' : 'gen',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        }
    ]

    requests_opt = [
        (
            ('/static/index.html'),
            ('referer'),
            ('example.com'),
            False
        ),
        (
            ('/script.php'),
            ('referer'),
            ('http://example.com/cgi-bin/show.pl'),
            False
        ),
        (
            ('/foo/example.com'),
            ('host'),
            ('test.app.com'),
            False
        ),
        (
            ('/bar/index.html'),
            ('user-agent'),
            ('Mozilla/60.0'),
            False
        ),
        (
            ('/static/foo/app/test.php'),
            ('host'),
            ('bar.example.com'),
            False
        ),
        (
            ('/app/hacked.com'),
            ('referer'),
            ('http://example.com'),
            True
        ),
        (
            ('/'),
            ('host'),
            ('bad.host.com'),
            True
        )
    ]

    chains = []
    match_rules_test = True

    def init_chain(self, (uri, header, value, block)):
        ch = chains.base(uri=uri)
        if block and self.match_rules_test:
            ch.fwd_request = None
        else:
            for request in [ch.request, ch.fwd_request]:
                request.headers.delete_all(header)
                request.headers.add(header, value)
                request.update()
        self.chains.append(ch)

    def init_server(self, id, srv_response):
        srv = {}
        srv['id'] = id
        srv['type'] = 'deproxy'
        srv['port'] = str(8000 + id)
        srv['response'] = 'static'
        srv['response_content'] = srv_response.msg
        self.backends.append(srv)

    def setUp(self):
        del(self.chains[:])
        del(self.backends[:])
        count = len(self.requests_opt)
        for i in range(count):
            self.init_chain(self.requests_opt[i])
            self.init_server(i, self.chains[i].server_response)
        tester.TempestaTest.setUp(self)

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.assertTrue(self.wait_all_connections())
        self.get_client('gen').start()

    def process(self, client, server, chain):
        client.make_request(chain.request.msg)
        client.wait_for_response(timeout=5)
        if chain.fwd_request:
            chain.fwd_request.set_expected()
        self.assertEqual(server.last_request, chain.fwd_request)

    def test_chains(self):
        """Test for matching rules in HTTP chains: according to
        test configuration of HTTP tables, requests must be
        forwarded to the right vhosts according to it's
        headers content.
        """
        self.start_all()
        count = len(self.chains)
        for i in range(count):
            self.process(self.get_client('gen'),
                         self.get_server(i),
                         self.chains[i])

class HttpTablesTestMarkRules(HttpTablesTest):

    match_rules_test = False

    def set_nf_mark(self, mark):
        cmd = 'iptables -t mangle -A PREROUTING -p tcp -j MARK --set-mark %s' \
              % mark
        remote.tempesta.run_cmd(cmd, timeout=30)

    def del_nf_mark(self, mark):
        cmd = 'iptables -t mangle -D PREROUTING -p tcp -j MARK --set-mark %s' \
              % mark
        remote.tempesta.run_cmd(cmd, timeout=30)

    def test_chains(self):
        """Test for mark rules in HTTP chains: requests must
        arrive to backends in reverse order, since mark rules are
        always processed before match rule (see HTTP tables
        configuration for current test - in @tempesta
        class variable).
        """
        self.start_all()
        count = len(self.chains)
        for i in range(count):
            mark = i + 1
            self.set_nf_mark(mark)
            self.process(self.get_client('gen'),
                         self.get_server(count - mark),
                         self.chains[i])
            self.del_nf_mark(mark)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
