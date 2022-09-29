from h2.exceptions import ProtocolError
from helpers import deproxy, tf_cfg, tempesta, chains
from testers import functional
from framework import tester, deproxy_client

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017-2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

def sample_rule():
    return chains.base()

def sample_rule_chunked():
    return chains.base_chunked()

def defconfig():
    return 'cache 0;\n'


class DeproxyDummyTest(functional.FunctionalTest):
    """Test Deproxy, don't even start or setup TempestaFw in this test."""

    def setUp(self):
        self.client = None
        self.servers = []
        self.tester = None
        tf_cfg.dbg(3) # Step to the next line after name of test case.
        tf_cfg.dbg(3, '\tInit test case...')

    def tearDown(self):
        if self.client:
            self.client.stop()
        if self.tester:
            self.tester.stop()

    def create_clients(self):
        port = tempesta.upstream_port_start_from()
        self.client = deproxy.Client(port=port, host='Client')

    def create_servers(self):
        port = tempesta.upstream_port_start_from()
        self.servers = [deproxy.Server(port=port, conns_n=1)]

    def create_tester(self):
        self.tester = deproxy.Deproxy(self.client, self.servers)

    def routine(self, message_chains):
        self.create_servers()
        self.create_clients()
        self.create_tester()
        self.client.start()
        self.tester.start()

        self.tester.run()

    def test_deproxy_one_chain(self):
        chain = sample_rule()
        # In this test we do not have proxy
        chain.response = chain.server_response
        chain.fwd_request = chain.request

        message_chains = [chain]
        self.routine(message_chains)


class DeproxyTest(functional.FunctionalTest):

    def test_deproxy_one_chain(self):
        message_chains = [sample_rule()]
        self.generic_test_routine(defconfig(), message_chains)


class DeproxyChunkedTest(functional.FunctionalTest):

    def test_deproxy_one_chain(self):
        message_chains = [sample_rule_chunked()]
        self.generic_test_routine(defconfig(), message_chains)


class DeproxyTestFailOver(DeproxyTest):

    def create_servers(self):
        port = tempesta.upstream_port_start_from()
        self.servers = [deproxy.Server(port=port, keep_alive=1)]

    def create_tester(self):

        class DeproxyFailOver(deproxy.Deproxy):
            def check_expectations(self):
                # We closed server connection after response. Tempesta must
                # failover the connection. Run loop with small timeout
                # once again to process events.
                self.loop(0.1)
                assert self.is_srvs_ready(), 'Failovering failed!'
                deproxy.Deproxy.check_expectations(self)

        self.tester = DeproxyFailOver(self.client, self.servers)

class DeproxyTestH2(tester.TempestaTest):

    backends = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' :
            'HTTP/1.1 200 OK\r\n'
            'Content-Length: 0\r\n\r\n'
        }
    ]

    clients = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy_h2',
            'addr' : "${server_ip}",
            'port' : '443',
            'ssl'  : True,
            'ssl_hostname' : 'localhost'
        },
    ]

    tempesta = {
        'config' :
        """
        listen 443 proto=h2;
        server ${server_ip}:8000;

        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;

        tls_match_any_server_name;

        """
    }

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.start_all_clients()
        self.assertTrue(self.wait_all_connections())

    def test_make_request(self):
        self.start_all()

        head = [
            (':authority', 'localhost'),
            (':path', '/'),
            (':scheme', 'https'),
            (':method', 'GET')
        ]
        deproxy_cl = self.get_client('deproxy')
        deproxy_cl.parsing = True
        deproxy_cl.make_request(head)

        self.assertTrue(deproxy_cl.wait_for_response(timeout=0.5))
        self.assertIsNotNone(deproxy_cl.last_response)
        self.assertEqual(deproxy_cl.last_response.status, '200')

    def test_parsing_make_request(self):
        self.start_all()

        head = [
            (':authority', 'localhost'),
            (':path', '/'),
            (':scheme', 'http'),
            ('method', 'GET')
        ]
        deproxy_cl = self.get_client('deproxy')
        deproxy_cl.parsing = True

        self.assertRaises(
            ProtocolError,
            deproxy_cl.make_request,
            head
        )
        self.assertIsNone(deproxy_cl.last_response)

    def test_no_parsing_make_request(self):
        self.start_all()

        head = [
            (':authority', 'localhost'),
            (':path', '/'),
            (':method', 'GET'),
        ]
        deproxy_cl = self.get_client('deproxy')
        deproxy_cl.parsing = False

        deproxy_cl.make_request(head)
        self.assertFalse(deproxy_cl.wait_for_response(timeout=0.5))
        self.assertIsNone(deproxy_cl.last_response)

    def test_bodyless(self):
        self.start_all()

        head = [
            (':authority', 'localhost'),
            (':path', '/'),
            (':scheme', 'https'),
            (':method', 'GET')
        ]

        deproxy_cl = self.get_client('deproxy')
        deproxy_cl.make_request(head)

        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertEqual(deproxy_cl.last_response.status, '200')

    def test_bodyless_multiplexed(self):
        self.start_all()

        head = [
            (':authority', 'localhost'),
            (':path', '/'),
            (':scheme', 'https'),
            (':method', 'GET')
        ]
        request = [head, head]

        deproxy_srv = self.get_server('deproxy')
        deproxy_cl = self.get_client('deproxy')
        deproxy_cl.make_requests(request)

        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertEqual(2, len(deproxy_cl.responses))
        self.assertEqual(2, len(deproxy_srv.requests))

    def test_with_body(self):
        self.start_all()

        body = 'body body body'
        head = [
            (':authority', 'localhost'),
            (':path', '/'),
            (':scheme', 'https'),
            (':method', 'POST'),
            ('conent-length', '14')
        ]
        request = (head, body)

        deproxy_cl = self.get_client('deproxy')
        deproxy_cl.make_request(request)

        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertEqual(deproxy_cl.last_response.status, '200')


class DeproxyClientTest(tester.TempestaTest):

    backends = [
        {
            'id': 'deproxy',
            'type': 'deproxy',
            'port': '8000',
            'response': 'static',
            'response_content':
                'HTTP/1.1 200 OK\r\n'
                'Content-Length: 0\r\n'
                'Server: deproxy\r\n\r\n',
        },
    ]

    clients = [
        {
            'id': 'deproxy',
            'type': 'deproxy',
            'addr': "${tempesta_ip}",
            'port': '80'
        },
    ]

    tempesta = {
        'config': """
cache 0;
listen 80;

server ${server_ip}:8000;
"""
    }

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.start_all_clients()
        self.assertTrue(self.wait_all_connections())

    def test_make_request(self):
        self.start_all()
        client: deproxy_client.DeproxyClient = self.get_client('deproxy')
        client.parsing = True

        client.make_request('GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
        client.wait_for_response(timeout=0.5)

        self.assertIsNotNone(client.last_response)
        self.assertEqual(client.last_response.status, '200')

    def test_parsing_make_request(self):
        self.start_all()
        client: deproxy_client.DeproxyClient = self.get_client('deproxy')
        client.parsing = True

        self.assertRaises(
            deproxy.ParseError,
            client.make_request,
            'GETS / HTTP/1.1\r\nHost: localhost\r\n\r\n'
        )
        self.assertIsNone(client.last_response)

    def test_no_parsing_make_request(self):
        self.start_all()
        client: deproxy_client.DeproxyClient = self.get_client('deproxy')
        client.parsing = False

        client.make_request('GET / HTTP/1.1\r\nHost: local<host\r\n\r\n')
        client.wait_for_response(timeout=0.5)

        self.assertIsNotNone(client.last_response)
        self.assertEqual(client.last_response.status, '400')

    def test_many_make_request(self):
        self.start_all()
        client: deproxy_client.DeproxyClient = self.get_client('deproxy')
        client.parsing = True

        messages = 5
        for _ in range(0, messages):
            client.make_request('GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
            client.wait_for_response(timeout=0.5)

        self.assertEqual(len(client.responses), messages)
        for res in client.responses:
            self.assertEqual(res.status, '200')

    def test_many_make_request_2(self):
        self.start_all()
        client: deproxy_client.DeproxyClient = self.get_client('deproxy')
        client.parsing = False

        messages = 5
        for _ in range(0, messages):
            client.make_request('GET / HTTP/1.1\r\nHost: local<host\r\n\r\n')
            client.wait_for_response(timeout=0.5)

        self.assertEqual(client.last_response.status, '400')
        self.assertEqual(len(client.responses), 1)

    def test_make_requests(self):
        self.start_all()
        client: deproxy_client.DeproxyClient = self.get_client('deproxy')
        client.parsing = True

        request = 'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n'

        messages = 5
        client.make_requests(request * messages)
        client.wait_for_response(timeout=3)

        self.assertEqual(len(client.responses), messages)
        for res in client.responses:
            self.assertEqual(res.status, '200')

    def test_parsing_make_requests(self):
        self.start_all()
        client: deproxy_client.DeproxyClient = self.get_client('deproxy')
        client.parsing = True

        self.assertRaises(
            deproxy.ParseError,
            client.make_requests,
            [
                'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n',
                'GETS / HTTP/1.1\r\nHost: localhost\r\n\r\n',
            ]
        )
        self.assertIsNone(client.last_response)


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
