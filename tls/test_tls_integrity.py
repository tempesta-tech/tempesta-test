# Tests for data integrity transfered via Tempesta TLS.
import os

from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


REQUEST = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"

class SimpleIO(tester.TempestaTest):

    clients = [
        {
            'id' : 0,
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl' : True,
        },
    ]

    def setUp(self):
        dir_path = os.path.dirname(os.path.abspath(__file__))
        self.tempesta = {
            'config' : """
                cache 0;
                listen 443 proto=https;
                tls_certificate %s/tfw-root.crt;
                tls_certificate_key %s/tfw-root.key;
                server ${server_ip}:8000;
            """ % (dir_path, dir_path),
        }
        self.backends = [
            {
                'id' : '0',
                'type' : 'deproxy',
                'port' : '8000',
                'response' : 'static',
                'response_content' : # TODO callbacks ~ #96 ?
                    'HTTP/1.1 200 OK\r\n'
                    'Content-Length: 0\r\n'
                    'Connection: keep-alive\r\n\r\n'
            }
        ]
        tester.TempestaTest.setUp(self)

    def test(self):
        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()

        client = self.get_client(0)
        client.make_request(REQUEST)
        resp = client.wait_for_response(timeout=5)
        print("RESPONSE:", resp)

        res = True
        self.assertEqual(res, True, "Bad response checksum")
