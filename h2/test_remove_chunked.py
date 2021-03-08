"""
Chunked encoding is not supported by h2 protocol, since h2 has it's own framing
and chunked coding. Check that chunked encoding is stripped from http/1
responses.
"""

import unittest
from helpers import deproxy
from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2020 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

TEMPESTA_CONFIG = """
listen 443 proto=h2;

srv_group default {
    server ${server_ip}:8000;
}
vhost default {
    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;

    proxy_pass default;
}
"""

TEMPESTA_CONFIG_CACHING = """
listen 443 proto=h2;

srv_group default {
    server ${server_ip}:8000;
}
vhost default {
    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;

    proxy_pass default;
}

cache 2;
cache_fulfill * *;
"""

class RemoveChunked(tester.TempestaTest):
    """Remodve chunked encoding from http/1 responses and correctly frame them
    as h2 messages. Currently we have no good checker for http2 as deproxy,
    just cun curl and see if it's happy with the received response.
    """

    clients = [
        {
            'id' : 'curl',
            'type' : 'external',
            'binary' : 'curl',
            'cmd_args' : (
                '-kf ' # Set non-null return code on 4xx-5xx responses.
                'https://${tempesta_ip}/ '
                )
        },
    ]

    backends = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' : ''
        }
    ]

    tempesta = {
        'config' : TEMPESTA_CONFIG,
    }

    @staticmethod
    def gen_body(body_len=0):
        return ''.join([chr(i % 26 + ord('a')) for i in range(body_len)])

    @staticmethod
    def chunked_body(body, lowercase=False):
        fmt = "%x" if lowercase else "%X"
        if body:
            chunked_body = '\r\n'.join([fmt % len(body), body, '0', '', ''])
        else:
            chunked_body = '\r\n'.join(['0', '', ''])
        return chunked_body

    def send_reqs(self):
        srv = self.get_server('deproxy')
        curl = self.get_client('curl')

        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(srv.wait_for_connections(1))

        self.start_all_clients()
        self.wait_while_busy(curl)


    def test_small_resp(self):
        srv = self.get_server('deproxy')

        date = deproxy.HttpMessage.date_time_string()
        body = self.gen_body(40)
        chunked_body = self.chunked_body(body)
        resp = ('HTTP/1.1 200 OK\r\n'
                'Connection: keep-alive\r\n'
                'Content-type: text/html\r\n'
                'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
                'Server: Deproxy Server\r\n'
                'Transfer-Encoding: chunked\r\n'
                'Date: %s\r\n'
                '\r\n%s'
                % (date, chunked_body))
        srv.set_response(resp)

        self.send_reqs()

    @unittest.skip("Python hungs and eats 100% cpu, manual checks show no issues")
    def test_huge_resp(self):
        srv = self.get_server('deproxy')

        date = deproxy.HttpMessage.date_time_string()
        body = self.gen_body(32*4096)
        chunked_body = self.chunked_body(body)
        resp = ('HTTP/1.1 200 OK\r\n'
                'Connection: keep-alive\r\n'
                'Content-type: text/html\r\n'
                'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
                'Server: Deproxy Server\r\n'
                'Transfer-Encoding: chunked\r\n'
                'Date: %s\r\n'
                '\r\n%s'
                % (date, chunked_body))
        srv.set_response(resp)

        self.send_reqs()


    def test_zero_body_resp(self):
        srv = self.get_server('deproxy')

        date = deproxy.HttpMessage.date_time_string()
        body = self.gen_body(0)
        chunked_body = self.chunked_body(body)
        resp = ('HTTP/1.1 200 OK\r\n'
                'Connection: keep-alive\r\n'
                'Content-type: text/html\r\n'
                'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
                'Server: Deproxy Server\r\n'
                'Transfer-Encoding: chunked\r\n'
                'Date: %s\r\n'
                '\r\n%s'
                % (date, chunked_body))
        srv.set_response(resp)

        self.send_reqs()


    def test_heavily_chunked_resp(self):
        srv = self.get_server('deproxy')

        date = deproxy.HttpMessage.date_time_string()
        chunk_len = 40
        chunks = 10
        body = ''
        chunk = self.gen_body(chunk_len)
        chunk_desc = '%X\r\n%s\r\n' % (len(chunk), chunk)
        for _ in range(chunks):
            body += chunk_desc
        body += '0\r\n\r\n'
        resp = ('HTTP/1.1 200 OK\r\n'
                'Connection: keep-alive\r\n'
                'Content-type: text/html\r\n'
                'Last-Modified: Mon, 12 Dec 2016 13:59:39 GMT\r\n'
                'Server: Deproxy Server\r\n'
                'Transfer-Encoding: chunked\r\n'
                'Date: %s\r\n'
                '\r\n%s'
                % (date, body))
        srv.set_response(resp)

        self.send_reqs()


class RemoveChunkedCached(RemoveChunked):
    """All the previous tests checked that responses are forwarded without
    issues. Now enable caching and send two requests one-by one, second will
    hit the cache.
    """

    clients = [
        {
            'id' : 'curl',
            'type' : 'external',
            'binary' : 'curl',
            'cmd_args' : (
                '-kf ' # Set non-null return code on 4xx-5xx responses.
                'https://${tempesta_ip}/ https://${tempesta_ip}/'
                )
        },
    ]

    backends = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' : ''
        }
    ]

    tempesta = {
        'config' : TEMPESTA_CONFIG_CACHING,
    }
