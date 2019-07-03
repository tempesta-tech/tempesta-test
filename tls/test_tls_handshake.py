"""
Tests for valid and invalid TLS handhshakes, various violations in
handshake messages.
"""
from framework import tester
from handshake import tls12_hs, tls_old_hs

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class TlsHandshake(tester.TempestaTest):
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

    tempesta = {
        'config' : """
            cache 0;
            listen 443 proto=https;
            tls_certificate ${general_workdir}/tempesta.crt;
            tls_certificate_key ${general_workdir}/tempesta.key;
            server ${server_ip}:8000;
        """
    }

    def test_tls12_synthetic(self):
        self.start_all_servers()
        self.start_tempesta()

        res = tls12_hs({
            'addr':     '127.0.0.1',
            'port':     443,
            'rto':      0.5,
            'verbose':  False # use True for verbose handshake exchange
        })
        self.assertTrue(res, "Wrong handshake result: %s" % res)

    def test_old_handshakes(self):
        self.start_all_servers()
        self.start_tempesta()

        res = tls_old_hs({
            'addr':     '127.0.0.1',
            'port':     443,
            'rto':      0.5,
            'verbose':  False # use True for verbose handshake exchange
        })
        self.assertTrue(res, "Wrong old handshake result: %s" % res)
