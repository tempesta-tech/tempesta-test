from helpers import tf_cfg, deproxy, chains
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
        }
        http_chain {
        hdr_host == "test.app.com" -> chain2;
        hdr_uagent == "Mozilla*" -> chain2;
        hdr_ref == "*.com" -> chain1;
        hdr_ref == "http://example.*" -> chain3;
        hdr_host == "bar*" -> vh5;
        mark == 1 -> vh5;
        mark == 2 -> vh4;
        mark == 3 -> vh3;
        mark == 4 -> vh2;
        mark == 5 -> vh1;
        }
        """
    }

    chains = []

    requests_opt = [
        (('/static/index.html'), ('referer'), ('example.com')),
        (('/script.php'), ('referer'), ('http://example.com/cgi-bin/show.pl')),
        (('/foo/example.com'), ('host'), ('test.app.com')),
        (('/bar/index.html'), ('User-Agent'), ('Mozilla/60.0')),
        (('/'), ('host'), ('bar.example.com'))
    ]

    def init_chain(self, (uri, header, value)):
        ch = chains.base(uri=uri)
        if header:
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

    def init_client(self, id):
        cl = {}
        cl['id'] = id
        cl['type'] = 'deproxy'
        cl['addr'] = "${tempesta_ip}"
        cl['port'] = '80'
        self.clients.append(cl)

    def setUp(self):
        del(self.chains[:])
        del(self.backends[:])
        del(self.clients[:])
        count = len(self.requests_opt)
        for i in range(count):
            self.init_chain(self.requests_opt[i])
            self.init_server(i, self.chains[i].server_response)
            self.init_client(i)
        tester.TempestaTest.setUp(self)

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.wait_all_connections()
        self.start_all_clients()

    def process(self, client, server, chain):
        client.make_request(chain.request.msg)
        client.wait_for_response(timeout=5)
        chain.fwd_request.set_expected()
        self.assertEqual(server.last_request, chain.fwd_request)

    def test_chains_match(self):
        """Test for matching rules in HTTP chains: according to
        test configuration of HTTP tables, requests should arrive to
        backends in direct order.
        """
        self.start_all()
        count = len(self.chains)
        for i in range(count):
            self.process(self.get_client(i),
                         self.get_server(i),
                         self.chains[i])

    def test_chains_mark(self):
        """Test for mark rules in HTTP chains: requests should arrive
        to backends in reverse order, since mark rules are always processed
        before match rule (see HTTP tables configuration for current
        test - in @tempesta class variable).
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
