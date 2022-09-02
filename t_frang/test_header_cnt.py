"""Tests for Frang directive `http_header_cnt`."""
from t_frang.frang_test_case import ONE, FrangTestCase
import time
from requests import request
from framework import tester
from helpers import dmesg

ERROR = "Warning: frang: HTTP headers number exceeded for"

class FrangHttpHeaderCountTestCase(FrangTestCase):
    """Tests for 'http_header_cnt' directive."""

    clients = [
        {
            'id': 'curl-1',
            'type': 'external',
            'binary': 'curl',
            'cmd_args': '''-Ikf -v http://127.0.0.4:8765/ 
                            -H "Host: tempesta-tech.com:8765" 
                            -H "Connection: keep-alive"
                            -H "Content-Type: text/html"
                            -H "Transfer-Encoding: chunked"
                            ''',  
        },
        {
            'id': 'curl-2',
            'type': 'external',
            'binary': 'curl',
            'cmd_args': '''-Ikf -v http://127.0.0.4:8765/ 
                            -H "Host: tempesta-tech.com:8765" 
                            -H "Connection: keep-alive"
                            ''',  
        },
        {
            'id': 'curl-3',
            'type': 'external',
            'binary': 'curl',
            'cmd_args': '''-Ikf -v http://127.0.0.4:8765/ 
                            -H "Host: tempesta-tech.com:8765" 
                            -H "Connection: keep-alive"
                            -H "Content-Type: text/html"
                            ''',  
        },
    ]

    tempesta = {
        'config': """
            frang_limits {
                http_header_cnt 3;
            }

            listen 127.0.0.4:8765;

            srv_group default {
                server ${server_ip}:8000;
            }

            vhost tempesta-cat {
                proxy_pass default;
            }

            tls_match_any_server_name;
            tls_certificate RSA/tfw-root.crt;
            tls_certificate_key RSA/tfw-root.key;

            cache 0;
            cache_fulfill * *;
            block_action attack reply;

            http_chain {
                -> tempesta-cat;
            }
        """,
    }

    def test_reaching_the_limit(self):
        """
        Test 'client_header_timeout'.

        We set up for Tempesta `http_header_cnt 3` and
        made request with 4 headers
        """
        curl = self.get_client('curl-1')

        self.start_all_servers()
        self.start_tempesta()

        curl.start()
        self.wait_while_busy(curl)

        self.assertEqual(
            self.klog.warn_count(
                ERROR,
            ),
            ONE,
            'Expected msg in `journalctl`',
        )
        self.assertEqual(
            self.klog.warn_count(
                'Warning: parsed request has been filtered out',
            ),
            ONE,
            'Expected msg in `journalctl`',
        )

        curl.stop()


    def test_not_reaching_the_limit(self):
        """
        Test 'client_header_timeout'.

        We set up for Tempesta `http_header_cnt 3` and
        made request with 2 headers
        """
        curl = self.get_client('curl-2')

        self.start_all_servers()
        self.start_tempesta()

        curl.start()
        self.wait_while_busy(curl)

        self.assertEqual(
            self.klog.warn_count(
                ERROR,
            ),
            0,
            'Unexpected msg in `journalctl`',
        )
        self.assertEqual(
            self.klog.warn_count(
                'Warning: parsed request has been filtered out',
            ),
            0,
            'Unexpected msg in `journalctl`',
        )

        curl.stop()


    def test_ont_the_limit(self):
        """
        Test 'client_header_timeout'.

        We set up for Tempesta `http_header_cnt 3` and
        made request with 3 headers
        """
        curl = self.get_client('curl-3')

        self.start_all_servers()
        self.start_tempesta()

        curl.start()
        self.wait_while_busy(curl)

        self.assertEqual(
            self.klog.warn_count(
                ERROR,
            ),
            ONE,
            'Expected msg in `journalctl`',
        )
        self.assertEqual(
            self.klog.warn_count(
                'Warning: parsed request has been filtered out',
            ),
            ONE,
            'Expected msg in `journalctl`',
        )

        curl.stop()



class HttpHeaderCntBase(tester.TempestaTest):
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
            'interface' : True
        },
        {
            'id' : 'deproxy2',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80',
            'interface' : True
        }, 
        {
            'id' : 'deproxy3',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        },
        {
            'id' : 'deproxy4',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        }
    ]



class HttpHeaderCnt(HttpHeaderCntBase):
    tempesta = {
        'config' : """
server ${server_ip}:8000;

frang_limits {
    ip_block on;
    http_header_cnt 3;
}

""",
    }

    def test_two_clients_two_ip(self):

        requests = 'POST / HTTP/1.1\r\n' \
                'Host: debian\r\n' \
                'Content-Type: text/html\r\n' \
                'Transfer-Encoding: chunked\r\n' \
                'Connection: keep-alive\r\n' \
                '\r\n' 

        requests2 = 'POST / HTTP/1.1\r\n' \
                'Host: debian\r\n' \
                'Content-Type: text/html\r\n' \
                '\r\n'
        klog = dmesg.DmesgFinder(ratelimited=False)
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

        deproxy_cl.wait_for_response()
        deproxy_cl2.wait_for_response()
        self.assertEqual(klog.warn_count(ERROR), 1,
                          "Frang limits warning is not shown")


        self.assertEqual(0, len(deproxy_cl.responses))
        self.assertEqual(1, len(deproxy_cl2.responses))

        self.assertTrue(deproxy_cl.connection_is_closed())
        self.assertFalse(deproxy_cl2.connection_is_closed())


    def test_two_clients_one_ip(self):

        requests = 'POST / HTTP/1.1\r\n' \
                'Host: debian\r\n' \
                'Content-Type: text/html\r\n' \
                'Transfer-Encoding: chunked\r\n' \
                'Connection: keep-alive\r\n' \
                '\r\n' 

        requests2 = 'POST / HTTP/1.1\r\n' \
                'Host: debian\r\n' \
                'Content-Type: text/html\r\n' \
                '\r\n'
        klog = dmesg.DmesgFinder(ratelimited=False)
        nginx = self.get_server('nginx')
        nginx.start()
        self.start_tempesta()

        deproxy_cl = self.get_client('deproxy3')
        deproxy_cl.start()

        deproxy_cl2 = self.get_client('deproxy4')
        deproxy_cl2.start()


        self.deproxy_manager.start()
        self.assertTrue(nginx.wait_for_connections(timeout=1))

        deproxy_cl.make_requests(requests)
        deproxy_cl2.make_requests(requests2)

        deproxy_cl.wait_for_response()
        deproxy_cl2.wait_for_response()
        self.assertEqual(klog.warn_count(ERROR), 1,
                          "Frang limits warning is not shown")


        self.assertEqual(0, len(deproxy_cl.responses))
        self.assertEqual(1, len(deproxy_cl2.responses))

        self.assertTrue(deproxy_cl.connection_is_closed())
        self.assertTrue(deproxy_cl2.connection_is_closed())

