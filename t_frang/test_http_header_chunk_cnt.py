import time
from requests import request
from framework import tester
from helpers import dmesg

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'
ERROR = "Warning: frang: HTTP header chunk count exceeded"

class HttpHeaderChunkCntBase(tester.TempestaTest):
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
            'interface' : True,
            'segment_size': 1,
            'segment_gap': 100
        },
        {
            'id' : 'deproxy2',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80',
            'interface' : True,
            'segment_size': 0
        }, 
        {
            'id' : 'deproxy3',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80',
            'segment_size': 1,
            'segment_gap': 100
        },
        {
            'id' : 'deproxy4',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80',
            'rps': 5
        }
    ]



class HttpHeaderChunkCnt(HttpHeaderChunkCntBase):
    tempesta = {
        'config' : """
server ${server_ip}:8000;

frang_limits {
    http_header_chunk_cnt 2;
    ip_block on;
}

""",
    }
    def test_two_clients_two_ip(self):

        requests = "GET /uri1 HTTP/1.1\r\n" \
                   "Host: localhost\r\n" \
                   "\r\n"
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
        deproxy_cl2.make_requests(requests)

        deproxy_cl.wait_for_response()
        deproxy_cl2.wait_for_response()
        self.assertEqual(klog.warn_count(ERROR), 1,
                          "Frang limits warning is not shown")


        self.assertEqual(0, len(deproxy_cl.responses))
        self.assertEqual(1, len(deproxy_cl2.responses))

        self.assertTrue(deproxy_cl.connection_is_closed())
        self.assertFalse(deproxy_cl2.connection_is_closed())


    def test_two_clients_one_ip(self):

        requests = "GET /uri1 HTTP/1.1\r\n" \
                   "Host: localhost\r\n" \
                   "\r\n"
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
        deproxy_cl2.make_requests(requests)

        deproxy_cl.wait_for_response()
        deproxy_cl2.wait_for_response()
        self.assertEqual(klog.warn_count(ERROR), 1,
                          "Frang limits warning is not shown")


        self.assertEqual(0, len(deproxy_cl.responses))
        self.assertEqual(1, len(deproxy_cl2.responses))

        self.assertFalse(deproxy_cl.connection_is_closed())
        self.assertFalse(deproxy_cl2.connection_is_closed())
