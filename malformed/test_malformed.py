from framework import tester
from helpers import tf_cfg, deproxy

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class MalformedRequestsTest(tester.TempestaTest):
    backends = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' :
"""HTTP/1.1 200 OK
Content-Length: 0
Connection: close

"""
        },
    ]

    tempesta = {
        'config' : """
cache 0;
listen 80;

srv_group default {
    server ${general_ip}:8000;
}

vhost default {
    proxy_pass default;
}
""",
    }

    clients = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        },
    ]

    def common_check(self, request):
        deproxy = self.get_server('deproxy')
        deproxy.start()
        self.start_tempesta()
        self.assertTrue(deproxy.wait_for_connections(timeout=1))
        deproxy = self.get_client('deproxy')
        deproxy.start()
        deproxy.make_request(request)
        resp = deproxy.wait_for_response(timeout=5)
        self.assertTrue(resp, "Response not received")
        status = deproxy.last_response.status
        self.assertEqual(int(status), 400, "Wrong status: %s" % status)

    def test_accept(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Accept: invalid\r\n' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_accept_charset(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Accept-Charset: invalid\r\n' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_accept_encoding(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Accept-Encoding: invalid\r\n' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_accept_language(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Accept-Language: 123456789\r\n' \
                  '\r\n\r\n'
        self.common_check(request)

    # Authorization

    def test_cache_control(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Cache-Control: invalid\r\n' \
                  '\r\n\r\n'
        self.common_check(request)

    # not test for 'Connection' header.

    def test_content_encoding(self):
        request = 'POST / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Content-Encoding: invalid\r\n' \
                  'Content-Length: 0\r\n' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_content_language(self):
        request = 'POST / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Content-Language: 123456789\r\n' \
                  'Content-Length: 0\r\n' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_content_length(self):
        request = 'POST / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Content-Length: not a number\r\n' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_content_location(self):
        request = 'POST / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Content-Location: not a uri\r\n' \
                  'Content-Length: 0\r\n' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_content_md5(self):
        request = 'POST / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Content-MD5: invalid\r\n' \
                  'Content-Length: 0\r\n' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_content_range(self):
        request = 'POST / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Content-Range: invalid\r\n' \
                  'Content-Length: 0\r\n' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_content_type(self):
        request = 'POST / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Content-Type: invalid\r\n' \
                  'Content-Length: 0\r\n' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_date(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Date: invalid\r\n' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_expect(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Expect: invalid\r\n' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_from(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'From: not a email\r\n' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_host(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: \r\n' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_if_match(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'If-Match: not in quotes\r\n' \
                  'Content-Length: 0\r\n' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_if_modified_since(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'If-Modified-Since: invalid\r\n' \
                  'Content-Length: 0\r\n' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_if_none_match(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'If-None-Match: not in quotes\r\n' \
                  'Content-Length: 0\r\n' \
                  '\r\n\r\n'
        self.common_check(request)
    
    def test_if_range(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'If-Range: not in quotes\r\n' \
                  'Content-Length: 0\r\n' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_if_unmodified_since(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'If-Unmodified-Since: invalid\r\n' \
                  'Content-Length: 0\r\n' \
                  '\r\n\r\n'
        self.common_check(request)

    
    def test_last_modified(self):
        request = 'POST / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Last-Modified: invalid\r\n' \
                  'Content-Length: 0\r\n' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_max_forwards(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Max-Forwards: not a number' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_pragma(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Pragma: invalid' \
                  '\r\n\r\n'
        self.common_check(request)

    # Proxy-Authorization

    def test_range(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Range: invalid' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_referer(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Referer: not a uri' \
                  '\r\n\r\n'
        self.common_check(request)

    # TE

    def test_trailer1(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Trailer: Trailer' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_trailer2(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Trailer: Content-Length' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_trailer3(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Trailer: Transfer-Encoding' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_transfer_encoding(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Transfer-Encoding: invalid' \
                  '\r\n\r\n'
        self.common_check(request)
    
    # Upgrade

    # User-Agent

    # Via
