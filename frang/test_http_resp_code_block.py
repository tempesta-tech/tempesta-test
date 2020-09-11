"""
Functional tests for http_resp_code_block.
If your web application works with user accounts, then typically it requires
a user authentication. If you implement the user authentication on your web
site, then an attacker may try to use a brute-force password cracker to get
access to accounts of your users. The second case is much harder to detect.
It's worth mentioning that unsuccessful authorization requests typically
produce error HTTP responses.

Tempesta FW provides http_resp_code_block for efficient blocking of all types of
password crackers
"""

from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class HttpRespCodeBlockBase(tester.TempestaTest):
    backends = [
        {
            'id' : 'nginx',
            'type' : 'nginx',
            'status_uri' : 'http://${server_ip}:8000/nginx_status',
            'config' : """
pid ${pid};
worker_processes  auto;

events {
    worker_connections   1024;
    use epoll;
}

http {
    keepalive_timeout ${server_keepalive_timeout};
    keepalive_requests 10;
    sendfile         on;
    tcp_nopush       on;
    tcp_nodelay      on;

    open_file_cache max=1000;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors off;

    # [ debug | info | notice | warn | error | crit | alert | emerg ]
    # Fully disable log errors.
    error_log /dev/null emerg;

    # Disable access log altogether.
    access_log off;

    server {
        listen        ${server_ip}:8000;

        location /uri1 {
            return 404;
        }
        location /uri2 {
            return 200;
        }
        location /nginx_status {
            stub_status on;
        }
    }
}
""",
        }
    ]

    clients = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80',
            'interface' : True,
            'rps': 6
        },
        {
            'id' : 'deproxy2',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80',
            'interface' : True,
            'rps': 5
        },
    ]


class HttpRespCodeBlock(HttpRespCodeBlockBase):
    """Blocks an attacker's IP address if a protected web application return
    5 error responses with codes 404 within 2 seconds. This is 2,5 per second.
    """
    tempesta = {
        'config' : """
server ${server_ip}:8000;

frang_limits {
    http_resp_code_block 404 5 2;
}
""",
    }

    """Two clients. One client sends 12 requests by 6 per second during
    2 seconds. Of these, 6 requests by 3 per second give 404 responses and
    should be blocked after 10 responses (5 with code 200 and 5 with code 404).
    The second client sends 20 requests by 5 per second during 4 seconds.
    Of these, 10 requests by 2.5 per second give 404 responses and should not be
    blocked.
    """
    def test(self):
        requests = "GET /uri1 HTTP/1.1\r\n" \
                   "Host: localhost\r\n" \
                   "\r\n" \
                   "GET /uri2 HTTP/1.1\r\n" \
                   "Host: localhost\r\n" \
                   "\r\n" * 6
        requests2 = "GET /uri1 HTTP/1.1\r\n" \
                    "Host: localhost\r\n" \
                    "\r\n" \
                    "GET /uri2 HTTP/1.1\r\n" \
                    "Host: localhost\r\n" \
                    "\r\n" * 10
        nginx = self.get_server('nginx')
        nginx.start()
        self.start_tempesta()

        deproxy_cl = self.get_client('deproxy')
        deproxy_cl.start()

        deproxy_cl2 = self.get_client('deproxy2')
        deproxy_cl2.start()

        self.deproxy_manager.start()
        self.assertTrue(nginx.wait_for_connections(timeout=1))

        deproxy_cl.make_requests(requests)
        deproxy_cl2.make_requests(requests2)

        deproxy_cl.wait_for_response(timeout=2)
        deproxy_cl2.wait_for_response(timeout=4)

        self.assertEqual(10, len(deproxy_cl.responses))
        self.assertEqual(20, len(deproxy_cl2.responses))

        self.assertTrue(deproxy_cl.connection_is_closed())
        self.assertFalse(deproxy_cl2.connection_is_closed())

class HttpRespCodeBlockWithReply(HttpRespCodeBlockBase):
    """Tempesta must return appropriate error status if a protected web
    application return more 5 error responses with codes 404 within 2 seconds.
    This is 2,5 per second.
    """
    tempesta = {
        'config' : """
server ${server_ip}:8000;

frang_limits {
    http_resp_code_block 404 5 2;
}

block_action attack reply;
""",
    }

    """Two clients. One client sends 12 requests by 6 per second during
    2 seconds. Of these, 6 requests by 3 per second give 404 responses.
    Should be get 11 responses (5 with code 200, 5 with code 404 and
    1 with code 403).
    The second client sends 20 requests by 5 per second during 4 seconds.
    Of these, 10 requests by 2.5 per second give 404 responses. All requests
    should be get responses.
    """
    def test(self):
        requests = "GET /uri1 HTTP/1.1\r\n" \
                   "Host: localhost\r\n" \
                   "\r\n" \
                   "GET /uri2 HTTP/1.1\r\n" \
                   "Host: localhost\r\n" \
                   "\r\n" * 6
        requests2 = "GET /uri1 HTTP/1.1\r\n" \
                    "Host: localhost\r\n" \
                    "\r\n" \
                    "GET /uri2 HTTP/1.1\r\n" \
                    "Host: localhost\r\n" \
                    "\r\n" * 10
        nginx = self.get_server('nginx')
        nginx.start()
        self.start_tempesta()

        deproxy_cl = self.get_client('deproxy')
        deproxy_cl.start()

        deproxy_cl2 = self.get_client('deproxy2')
        deproxy_cl2.start()

        self.deproxy_manager.start()
        self.assertTrue(nginx.wait_for_connections(timeout=1))

        deproxy_cl.make_requests(requests)
        deproxy_cl2.make_requests(requests2)

        deproxy_cl.wait_for_response(timeout=2)
        deproxy_cl2.wait_for_response(timeout=4)

        self.assertEqual(11, len(deproxy_cl.responses))
        self.assertEqual(20, len(deproxy_cl2.responses))

        self.assertEqual('403', deproxy_cl.responses[-1].status,
                         "Unexpected response status code")

        self.assertTrue(deproxy_cl.connection_is_closed())
        self.assertFalse(deproxy_cl2.connection_is_closed())
