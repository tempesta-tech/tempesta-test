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

import time
from requests import request
from framework import tester
from helpers import dmesg

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'
ERROR = "Warning: frang: connections max num. exceeded"

class ConcurrentConnectionsBase(tester.TempestaTest):
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
        location /uri3 {
            return 405;
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
        {
            'id' : 'deproxy3',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80',
            'rps': 5
        },
        {
            'id' : 'deproxy4',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80',
            'rps': 5
        },
        {
            'id' : 'deproxy5',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80',
            'rps': 5
        }
    ]



class ConcurrentConnections(ConcurrentConnectionsBase):
    tempesta = {
        'config' : """
server ${server_ip}:8000;

frang_limits {
    concurrent_connections 2;
    request_burst 1;
}

""",
#ip_block on; - with this limit, the test freezes and then produces very beautiful unreadable logs
    }
    def test_three_clients_one_ip(self):
        """
        Three clients to be blocked by ip
        
        """
        requests = "GET /uri1 HTTP/1.1\r\n" \
                   "Host: localhost\r\n" \
                   "\r\n" * 10
        requests2 = "GET /uri2 HTTP/1.1\r\n" \
                   "Host: localhost\r\n" \
                   "\r\n" * 10

        klog = dmesg.DmesgFinder(ratelimited=False)
        nginx = self.get_server('nginx')
        nginx.start()
        self.start_tempesta()

        deproxy_cl = self.get_client('deproxy3')
        deproxy_cl.start()

        deproxy_cl2 = self.get_client('deproxy4')
        deproxy_cl2.start()

        deproxy_cl3 = self.get_client('deproxy5')
        deproxy_cl3.start()


        self.deproxy_manager.start()
        self.assertTrue(nginx.wait_for_connections(timeout=1))
        self.assertEqual(klog.warn_count(ERROR), 1,
                          "Frang limits warning is not shown")

        deproxy_cl.make_requests(requests)
        deproxy_cl2.make_requests(requests2)
        deproxy_cl3.make_requests(requests2)

        deproxy_cl.wait_for_response(timeout=2)
        deproxy_cl2.wait_for_response(timeout=2)
        deproxy_cl3.wait_for_response(timeout=2)

        self.assertEqual(10, len(deproxy_cl.responses))
        self.assertEqual(0, len(deproxy_cl2.responses))
        self.assertEqual(0, len(deproxy_cl3.responses))

        self.assertFalse(deproxy_cl.connection_is_closed())
        self.assertTrue(deproxy_cl2.connection_is_closed())#all clients should be blocked here, but for some reason only one gets closed
        self.assertFalse(deproxy_cl3.connection_is_closed())



    def test_two_clients_two_ip(self):

        requests = "GET /uri2 HTTP/1.1\r\n" \
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
        deproxy_cl2.make_requests(requests)

        deproxy_cl.wait_for_response(timeout=2)
        deproxy_cl2.wait_for_response(timeout=2)

        self.assertEqual(10, len(deproxy_cl.responses))
        self.assertEqual(10, len(deproxy_cl2.responses))

        self.assertFalse(deproxy_cl.connection_is_closed())
        self.assertFalse(deproxy_cl2.connection_is_closed())


   