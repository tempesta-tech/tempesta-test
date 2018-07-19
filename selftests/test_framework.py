import time

from helpers import tf_cfg, deproxy
from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class ExampleTest(tester.TempestaTest):
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
        {
            'id' : 'nginx',
            'type' : 'nginx',
            'status_uri' : 'http://${server_ip}:8000/nginx_status',
            'config' : """
pid ${backend_pid};
worker_processes  auto;

events {
    worker_connections   1024;
    use epoll;
}

http {
    keepalive_timeout ${server_keepalive_timeout};
    keepalive_requests ${server_keepalive_requests};
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
        listen        0.0.0.0:8000;

        location / {
            root $server_resources;
        }
        location /nginx_status {
            stub_status on;
        }
    }
}
""",
        }
    ]

    tempesta = {
        'config' : """
cache 0;
listen 80;

srv_group default {
    server ${server_ip}:8000;
}

vhost default {
    proxy_pass default;
}
""",
    }

    clients = [
        {
            'id' : 'wrk_0',
            'type' : 'wrk',
            'addr' : "${server_ip}:8000",
        },
        {
            'id' : 'wrk_1',
            'type' : 'wrk',
            'addr' : "${tempesta_ip}:80",
        },
        {
            'id' : 'wrk_2',
            'type' : 'wrk',
            'addr' : "${tempesta_ip}:80",
        },
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        },
        {
            'id' : 'deproxy_direct',
            'type' : 'deproxy',
            'addr' : "${server_ip}",
            'port' : '8000'
        },
    ]

    def test(self):
        """ Simple test """
        nginx = self.get_server('nginx')
        nginx.start()
        self.start_tempesta()
        self.assertTrue(nginx.wait_for_connections(timeout=1))
        wrk1 = self.get_client('wrk_1')
        wrk1.start()
        self.wait_while_busy(wrk1)

    def test2(self):
        """ Simple test 2 """
        nginx = self.get_server('nginx')
        nginx.start()
        self.start_tempesta()
        self.assertTrue(nginx.wait_for_connections(timeout=1))
        wrk1 = self.get_client('wrk_1')
        wrk2 = self.get_client('wrk_2')
        wrk1.start()
        wrk2.start()
        self.wait_while_busy(wrk1, wrk2)

    def test_deproxy_srv(self):
        """ Simple test with deproxy server """
        deproxy = self.get_server('deproxy')
        deproxy.start()
        self.start_tempesta()
        self.assertTrue(deproxy.wait_for_connections(timeout=1))
        wrk1 = self.get_client('wrk_1')
        wrk1.start()
        self.wait_while_busy(wrk1)

    def test_deproxy_srv_direct(self):
        """ Simple test with deproxy server """
        deproxy = self.get_server('deproxy')
        deproxy.start()
        wrk0 = self.get_client('wrk_0')
        wrk0.start()
        self.wait_while_busy(wrk0)

    def test_deproxy_client(self):
        """ Simple test with deproxy client """
        nginx = self.get_server('nginx')
        nginx.start()
        self.start_tempesta()
        self.assertTrue(nginx.wait_for_connections(timeout=1))
        deproxy = self.get_client('deproxy')
        deproxy.start()
        deproxy.make_request('GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
        deproxy.wait_for_response(timeout=5)
        tf_cfg.dbg(3, "nginx response:\n%s" % str(deproxy.response))

    def test_deproxy_client_direct(self):
        """ Simple test with deproxy client """
        nginx = self.get_server('nginx')
        nginx.start()
        deproxy = self.get_client('deproxy_direct')
        deproxy.start()
        deproxy.make_request('GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
        deproxy.wait_for_response(timeout=5)
        tf_cfg.dbg(3, "nginx response:\n%s" % str(deproxy.response))

    def test_deproxy_srvclient(self):
        """ Simple test with deproxy server """
        dsrv = self.get_server('deproxy')
        dsrv.start()
        self.start_tempesta()
        self.assertTrue(dsrv.wait_for_connections(timeout=1))
        cl = self.get_client('deproxy')
        cl.start()
        cl.make_request('GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
        cl.wait_for_response(timeout=5)
        tf_cfg.dbg(3, "deproxy response:\n%s" % str(cl.response))

    def test_deproxy_srvclient_direct(self):
        """ Simple test with deproxy server """
        dsrv = self.get_server('deproxy')
        dsrv.start()
        cl = self.get_client('deproxy_direct')
        cl.start()
        cl.make_request('GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
        cl.wait_for_response(timeout=5)
        tf_cfg.dbg(3, "deproxy response:\n%s" % str(cl.response))

    def test_deproxy_srvclient_direct_check(self):
        """ Simple test with deproxy server """
        dsrv = self.get_server('deproxy')
        dsrv.start()
        cl = self.get_client('deproxy_direct')
        cl.start()
        cl.make_request('GET / HTTP/1.1\r\nHost: localhost\r\n\r\n')
        cl.wait_for_response(timeout=5)
        # expected response
        send = deproxy.Response(dsrv.response)
        send.set_expected()
        self.assertEqual(cl.response, send)

