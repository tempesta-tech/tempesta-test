"""
Tests to verify correctness of matching multiple
similar headers in one request.
"""
from helpers import chains, remote
from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class DuplicatedHeadersMatchTest(tester.TempestaTest):

    backends = [
        {
            'id' : 0,
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' :
            'HTTP/1.1 200 OK\r\n'
            'Content-Length: 0\r\n\r\n'
        }
    ]

    tempesta = {
        'config' :
        """
        block_action attack reply;
        srv_group grp1 {
        server ${server_ip}:8000;
        }
        vhost vh1 {
        proxy_pass grp1;
        }
        http_chain {
        hdr X-Forwarded-For == "1.1.1.1" -> vh1;
        -> block;
        }
        """
    }
    
    headers_val = [
        (
            ('1.1.1.1'),
            ('2.2.2.2'),
            ('3.3.3.3')
        ),
        (
            ('2.2.2.2'),
            ('1.1.1.1'),
            ('3.3.3.3')
        ),
        (
            ('3.3.3.3'),
            ('2.2.2.2'),
            ('1.1.1.1')
        ),
    ]

    chains = []
    success_response_status = '200'
    fail_response_status    = '403'
    header_name = 'X-Forwarded-For'

    def add_client(self, cid):
        client = {
                'id' : cid,
                'type' : 'deproxy',
                'addr' : "${tempesta_ip}",
                'port' : '80'
            }
        self.clients.append(client)

    def init_chain(self, values):
        ch = chains.base(uri='/')
        ch.request.headers.delete_all(self.header_name)
        for value in values:
            ch.request.headers.add(self.header_name, value)
        ch.request.update()
        self.chains.append(ch)

    def setUp(self):
        del(self.chains[:])
        count = len(self.headers_val)
        for i in range(count):
            self.add_client(i)
            self.init_chain(self.headers_val[i])
        tester.TempestaTest.setUp(self)

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections())

    def send_request(self, client, chain, expected_resp):
        client.make_request(chain.request.msg)
        client.wait_for_response()
        self.assertEqual(client.last_response.status, expected_resp)

    def test_match_success(self):
        self.start_all()
        count = len(self.headers_val)
        for i in range(count):
            self.send_request(self.get_client(i),
                              self.chains[i],
                              self.success_response_status)

    def test_match_fail(self):
        self.start_all()
        ch = chains.base(uri='/')
        ch.request.headers.delete_all(self.header_name)
        ch.request.headers.add(self.header_name, '1.2.3.4')
        ch.request.update()
        self.send_request(self.get_client(0),
                          ch,
                          self.fail_response_status)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
