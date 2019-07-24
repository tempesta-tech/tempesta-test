"""
Tests for data integrity transfered via Tempesta TLS.
"""
import hashlib

from helpers import tf_cfg
from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class TlsIntegrityTester(tester.TempestaTest):

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
            'response_content' : 'dummy',
        }
    ]

    def start_all(self):
        deproxy_srv = self.get_server('deproxy')
        deproxy_srv.start()
        self.start_tempesta()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1),
                        "No connection from Tempesta to backends")
        self.start_all_clients()

    @staticmethod
    def make_resp(body):
        return  'HTTP/1.1 200 OK\r\n' \
                'Content-Length: ' + str(len(body)) + '\r\n' \
                'Connection: keep-alive\r\n\r\n' + body

    @staticmethod
    def make_req(req_len):
        return  'POST /' + str(req_len) + ' HTTP/1.1\r\n' \
                'Host: localhost\r\n' \
                'Content-Length: ' + str(req_len) + '\r\n' \
                '\r\n' + ('x' * req_len)

    def common_check(self, req_len, resp_len):
        resp_body = 'x' * resp_len
        hash1 = hashlib.md5(resp_body).digest()

        self.get_server('deproxy').set_response(self.make_resp(resp_body))

        for clnt in self.clients:
            client = self.get_client(clnt['id'])
            client.make_request(self.make_req(req_len))
            res = client.wait_for_response(timeout=5)
            self.assertTrue(res, "Cannot process request (len=%d) or response" \
                                 " (len=%d)" % (req_len, resp_len))
            resp = client.responses.pop().body
            tf_cfg.dbg(4, '\tDeproxy response (len=%d): %s...'
                    % (len(resp), resp[:100]))
            hash2 = hashlib.md5(resp).digest()
            self.assertTrue(hash1 == hash2, "Bad response checksum")


class Proxy(TlsIntegrityTester):

    tempesta = {
        'config' : """
            cache 0;
            listen 443 proto=https;
            tls_certificate ${general_workdir}/tempesta.crt;
            tls_certificate_key ${general_workdir}/tempesta.key;
            # TODO tls_fallback_default allow_any;
            server ${server_ip}:8000;
        """
    }

    def test_various_req_resp_sizes(self):
        self.start_all()
        self.common_check(1, 1)
        self.common_check(19, 19)
        self.common_check(567, 567)
        self.common_check(1755, 1755)
        self.common_check(4096, 4096)
        self.common_check(16380, 16380)
        self.common_check(65536, 65536)
        self.common_check(1000000, 1000000)


class Cache(TlsIntegrityTester):

    clients = [
        {
            'id' : 'clnt1',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl' : True,
        },
        {
            'id' : 'clnt2',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl' : True,
        },
        {
            'id' : 'clnt3',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl' : True,
        },
        {
            'id' : 'clnt4',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '443',
            'ssl' : True,
        },
    ]

    tempesta = {
        'config' : """
            cache 1;
            cache_fulfill * *;
            cache_methods POST;
            listen 443 proto=https;
            tls_certificate ${general_workdir}/tempesta.crt;
            tls_certificate_key ${general_workdir}/tempesta.key;
            # TODO tls_fallback_default allow_any;
            server ${server_ip}:8000;
        """
    }

    def test_various_req_resp_sizes(self):
        self.start_all()
        self.common_check(1, 1)
        self.common_check(19, 19)
        self.common_check(567, 567)
        self.common_check(1755, 1755)
        self.common_check(4096, 4096)
        self.common_check(16380, 16380)
        self.common_check(65536, 65536)
        self.common_check(1000000, 1000000)

