import hashlib

from helpers import tf_cfg
from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class TlsBasic(tester.TempestaTest):

    clients = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl' : True,
        },
    ]

    backends = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' :
                'HTTP/1.1 200 OK\r\n' \
                'Content-Length: 10\r\n' \
                'Connection: keep-alive\r\n\r\n'
                '0123456789'
        }
    ]

    tempesta = {
        'config' : """
            cache 0;
            listen 443 proto=https;
            tls_certificate ${general_workdir}/tempesta.crt;
            tls_certificate_key ${general_workdir}/tempesta.key;
            server ${server_ip}:8000;
        """
    }

    def start_all(self):
        deproxy_srv = self.get_server('deproxy')
        deproxy_srv.start()
        self.start_tempesta()
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1),
                        "No connection from Tempesta to backends")

    def test_bad_request(self):
        self.start_all()
        client = self.get_client('deproxy')
        client.make_request('GET / HTxTP/1.1\nHost: localhost\n\n')
        res = client.wait_for_response(timeout=1)
        self.assertTrue(res, "Cannot process request")
        status = client.last_response.status
        self.assertEqual(status, '400', "Wrong response status: %s" % status)

    def test_connection_close(self):
        self.start_all()
        client = self.get_client('deproxy')
        client.make_request('GET / HTTP/1.1\r\n'
                            'Host: localhost\r\n'
                            'Connection: close\r\n\r\n')
        res = client.wait_for_response(timeout=1)
        self.assertTrue(res, "Cannot process request")
        status = client.last_response.status
        self.assertEqual(status, '200', "Wrong response status: %s" % status)
