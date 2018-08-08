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

    # Cache-Control

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

    def test_expect1(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Expect: invalid\r\n' \
                  '\r\n\r\n'
        self.common_check(request)

    def test_expect2(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Expect: 100-continue\r\n' \
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
                  'Host: http://\r\n' \
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
                  'Max-Forwards: not a number\r\n' \
                  '\r\n\r\n'
        self.common_check(request)

    # Pragma

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

    # Trailer

    def test_transfer_encoding(self):
        request = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  'Transfer-Encoding: invalid' \
                  '\r\n\r\n'
        self.common_check(request)
    
    # Upgrade

    # User-Agent

    # Via

class MalformedResponsesTest(tester.TempestaTest):
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

    request = 'GET / HTTP/1.1\r\n' \
              'Host: localhost\r\n' \
              '\r\n'

    def common_check(self, response, request):
        deproxy = self.get_server('deproxy')
        deproxy.set_response(response)
        deproxy.start()
        self.start_tempesta()
        self.assertTrue(deproxy.wait_for_connections(timeout=1))
        deproxy = self.get_client('deproxy')
        deproxy.start()
        deproxy.make_request(request)
        resp = deproxy.wait_for_response(timeout=5)
        self.assertTrue(resp, "Response not received")
        status = deproxy.last_response.status
        self.assertEqual(int(status), 502, "Wrong status: %s" % status)

    def test_accept_ranges(self):
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Accept-Ranges: invalid\r\n' \
                   'Connection: close\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_age(self):
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Age: not a number\r\n' \
                   'Connection: close\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_allow(self):
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Allow: invalid\r\n' \
                   'Connection: close\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    # Alternates

    def test_content_encoding(self):
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Content-Length: 0\r\n' \
                   'Content-Encoding: invalid\r\n' \
                   'Connection: close\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_content_language(self):
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Content-Length: 0\r\n' \
                   'Content-Language: 123456789\r\n' \
                   'Connection: close\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_content_length(self):
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Content-Length: not a number\r\n' \
                   'Connection: close\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_content_location(self):
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Content-Length: 0\r\n' \
                   'Content-Location: not a uri\r\n' \
                   'Connection: close\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_content_range(self):
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Content-Length: 0\r\n' \
                   'Content-Range: invalid\r\n' \
                   'Connection: close\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_content_type(self):
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Content-Length: 0\r\n' \
                   'Content-Type: invalid\r\n' \
                   'Connection: close\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_date(self):
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Content-Length: 0\r\n' \
                   'Date: not a date\r\n' \
                   'Connection: close\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_etag(self):
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Content-Length: 0\r\n' \
                   'Etag: not in quotes\r\n' \
                   'Connection: close\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_expires(self):
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Content-Length: 0\r\n' \
                   'Expires: not a date\r\n' \
                   'Connection: close\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_last_modified(self):
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Content-Length: 0\r\n' \
                   'Last-Modified: not a date\r\n' \
                   'Connection: close\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    def test_location(self):
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Location: not a uri\r\n' \
                   'Connection: close\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    # Proxy-Authenticate
    
    def test_retry_after(self):
        response = 'HTTP/1.1 200 OK\r\n' \
                   'Retry-After: not a date' \
                   'Connection: close\r\n' \
                   '\r\n'
        self.common_check(response, self.request)

    # Server

    # Vary

    # WWW-Authenticate
