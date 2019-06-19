import os

from framework import tester
from handshake import tls12_hs

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class Tls12(tester.TempestaTest):
    backends = [
        {
            'id' : '0',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' :
                'HTTP/1.1 200 OK\r\n'
                'Content-Length: 0\r\n'
                'Connection: keep-alive\r\n\r\n'
        }
    ]

    def setUp(self):
        dir = os.path.dirname(os.path.abspath(__file__))
        self.tempesta = {
            'config' : """
                cache 0;
                listen 443 proto=https;
                tls_certificate %s/tfw-root.crt;
                tls_certificate_key %s/tfw-root.key;
                server ${server_ip}:8000;
            """ % (dir, dir),
        }
        tester.TempestaTest.setUp(self)

    def test_synthetic(self):
        self.start_all_servers()
        self.start_tempesta()

        r = tls12_hs({
            'addr':     '127.0.0.1',
            'port':     443,
            'rto':      0.5,
            'verbose':  False # use True for verbose handshake exchange
        })
        self.assertEqual(r, True, "Wrong handshake result: %s" % r)

