"""
Set of tests to verify correctness of requests redirection in HTTP table
(via sereral HTTP chains). Mark rules and match rules are also tested here
(in separate tests).
"""
from helpers import chains, remote
from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class HttpTablesTest(tester.TempestaTest):

    backends = [
        {
            'id' : 0,
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' :
            'HTTP/1.1 200 OK\r\n'
            'Content-Length: 0\r\n\r\n'
        },
        {
            'id' : 1,
            'type' : 'deproxy',
            'port' : '8001',
            'response' : 'static',
            'response_content' :
            'HTTP/1.1 200 OK\r\n'
            'Content-Length: 0\r\n\r\n'
        },
        {
            'id' : 2,
            'type' : 'deproxy',
            'port' : '8002',
            'response' : 'static',
            'response_content' :
            'HTTP/1.1 200 OK\r\n'
            'Content-Length: 0\r\n\r\n'
        },
        {
            'id' : 3,
            'type' : 'deproxy',
            'port' : '8003',
            'response' : 'static',
            'response_content' :
            'HTTP/1.1 200 OK\r\n'
            'Content-Length: 0\r\n\r\n'
        },
        {
            'id' : 4,
            'type' : 'deproxy',
            'port' : '8004',
            'response' : 'static',
            'response_content' :
            'HTTP/1.1 200 OK\r\n'
            'Content-Length: 0\r\n\r\n'
        },
        {
            'id' : 5,
            'type' : 'deproxy',
            'port' : '8005',
            'response' : 'static',
            'response_content' :
            'HTTP/1.1 200 OK\r\n'
            'Content-Length: 0\r\n\r\n'
        },
        {
            'id' : 6,
            'type' : 'deproxy',
            'port' : '8006',
            'response' : 'static',
            'response_content' :
            'HTTP/1.1 200 OK\r\n'
            'Content-Length: 0\r\n\r\n'
        }
    ]

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
        -> block;
        }
        http_chain {
        hdr Host == "test.app.com" -> chain2;
        hdr User-Agent == "Mozilla*" -> chain2;
        hdr Referer == "*.com" -> chain1;
        hdr referer == "http://example.*" -> chain3;
        hdr host == "bad.host.com" -> block;
        hdr host == "bar*" -> vh5;
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
            'id' : 0,
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        },
        {
            'id' : 1,
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        },
        {
            'id' : 2,
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        },
        {
            'id' : 3,
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        },
        {
            'id' : 4,
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        },
        {
            'id' : 5,
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        },
        {
            'id' : 6,
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
            ('http://example.org'),
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
            ch.request.headers.delete_all(header)
            ch.request.headers.add(header, value)
            ch.request.update()
            ch.fwd_request = None
        else:
            for request in [ch.request, ch.fwd_request]:
                request.headers.delete_all(header)
                request.headers.add(header, value)
                request.update()
        self.chains.append(ch)

    def setUp(self):
        del(self.chains[:])
        count = len(self.requests_opt)
        for i in range(count):
            self.init_chain(self.requests_opt[i])
        tester.TempestaTest.setUp(self)

    def wait_all_connections(self, tmt=1):
        sids = self.get_servers_id()
        for id in sids:
            srv = self.get_server(id)
            if not srv.wait_for_connections(timeout=tmt):
                return False
        return True

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.assertTrue(self.wait_all_connections())
        self.start_all_clients()

    def process(self, client, server, chain):
        client.make_request(chain.request.msg)
        client.wait_for_response()
        if chain.fwd_request:
            chain.fwd_request.set_expected()
        self.assertEqual(server.last_request, chain.fwd_request)
        # Check if the connection alive (general case) or
        # not (case of 'block' rule matching) after the main
        # message processing. Response 404 is enough here.
        post_chain = chains.base()
        client.make_request(post_chain.request.msg)
        if chain.fwd_request:
            self.assertTrue(client.wait_for_response())
        else:
            self.assertFalse(client.wait_for_response())

    def test_chains(self):
        """Test for matching rules in HTTP chains: according to
        test configuration of HTTP tables, requests must be
        forwarded to the right vhosts according to it's
        headers content.
        """
        self.start_all()
        count = len(self.chains)
        for i in range(count):
            self.process(self.get_client(i),
                         self.get_server(i),
                         self.chains[i])

class HttpTablesTestMarkRules(HttpTablesTest):

    match_rules_test = False

    def set_nf_mark(self, mark):
        cmd = 'iptables -t mangle -A PREROUTING -p tcp -j MARK --set-mark %s' \
              % mark
        remote.tempesta.run_cmd(cmd, timeout=30)
        self.marked = mark

    def del_nf_mark(self, mark):
        cmd = 'iptables -t mangle -D PREROUTING -p tcp -j MARK --set-mark %s' \
              % mark
        remote.tempesta.run_cmd(cmd, timeout=30)
        self.marked = None

    def setUp(self):
        self.marked = None
        HttpTablesTest.setUp(self)

    def tearDown(self):
        if self.marked:
            self.del_nf_mark(self.marked)
        tester.TempestaTest.tearDown(self)

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
            self.process(self.get_client(i),
                         self.get_server(count - mark),
                         self.chains[i])
            self.del_nf_mark(mark)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
