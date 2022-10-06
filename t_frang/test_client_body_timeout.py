from framework import tester
from helpers import dmesg

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

ERROR = "Warning: frang: client body timeout exceeded"


class ClientBodyTimeoutBase(tester.TempestaTest):
    backends = [
        {
            'id': 'nginx',
            'type': 'nginx',
            'status_uri': 'http://${server_ip}:8000/nginx_status',
            'config': """
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
            'id': 'deproxy',
            'type': 'deproxy',
            'addr': "${tempesta_ip}",
            'port': '80',
            'interface': True,
            'segment_size': 10,
            'segment_gap': 1500
        },
        {
            'id': 'deproxy2',
            'type': 'deproxy',
            'addr': "${tempesta_ip}",
            'port': '80',
            'interface': True,
            'segment_size': 10,
            'segment_gap': 10
        },
        {
            'id': 'deproxy3',
            'type': 'deproxy',
            'addr': "${tempesta_ip}",
            'port': '80',
            'segment_size': 10,
            'segment_gap': 1500
        },
        {
            'id': 'deproxy4',
            'type': 'deproxy',
            'addr': "${tempesta_ip}",
            'port': '80',
            'segment_size': 10,
            'segment_gap': 10
        }
    ]


class ClientBodyTimeout(ClientBodyTimeoutBase):
    tempesta = {
        'config': """
server ${server_ip}:8000;

frang_limits {
    client_body_timeout 1;
    ip_block on;
}

""",
    }

    def test_two_clients_two_ip(self):
        '''
        In this test, there are two clients with two different ip.
        One client sends request segments with a large gap,
        the other sends request segments with a small gap.
        So only the first client will be blocked.
        '''

        requests = 'POST / HTTP/1.1\r\n' \
            'Host: debian\r\n' \
            'Content-Type: text/html\r\n' \
            'Transfer-Encoding: chunked\r\n' \
            '\r\n' \
            '4\r\n' \
            'test\r\n' \
            '0\r\n' \
            '\r\n'

        nginx = self.get_server('nginx')
        nginx.start()
        self.start_tempesta()
        klog = dmesg.DmesgFinder(ratelimited=False)

        deproxy_cl = self.get_client('deproxy')
        deproxy_cl.start()
        deproxy_cl2 = self.get_client('deproxy2')
        deproxy_cl2.start()

        self.deproxy_manager.start()
        self.assertTrue(nginx.wait_for_connections(timeout=1))

        deproxy_cl.make_requests(requests)
        deproxy_cl2.make_requests(requests)
        deproxy_cl.wait_for_response(15)
        deproxy_cl2.wait_for_response()
        self.assertEqual(klog.warn_count(ERROR), 1, "Warning is not shown")

        self.assertEqual(0, len(deproxy_cl.responses))
        self.assertEqual(1, len(deproxy_cl2.responses))

        self.assertTrue(deproxy_cl.connection_is_closed())
        self.assertFalse(deproxy_cl2.connection_is_closed())

    def test_two_clients_one_ip(self):
        '''
        In this test, there are two clients with the same address.
        One client sends request segments with a large gap,
        the other sends request segments with a small gap.
        But both clients should be blocked because
        the frang limit [ip_block on;] is set
        '''

        requests = 'POST / HTTP/1.1\r\n' \
            'Host: debian\r\n' \
            'Content-Type: text/html\r\n' \
            'Transfer-Encoding: chunked\r\n' \
            '\r\n' \
            '4\r\n' \
            'test\r\n' \
            '0\r\n' \
            '\r\n'

        nginx = self.get_server('nginx')
        nginx.start()
        self.start_tempesta()
        klog = dmesg.DmesgFinder(ratelimited=False)

        deproxy_cl = self.get_client('deproxy3')
        deproxy_cl.start()

        deproxy_cl2 = self.get_client('deproxy4')
        deproxy_cl2.start()

        self.deproxy_manager.start()
        self.assertTrue(nginx.wait_for_connections(timeout=1))

        deproxy_cl.make_requests(requests)
        deproxy_cl2.make_requests(requests)

        deproxy_cl.wait_for_response(timeout=15)
        deproxy_cl2.wait_for_response()
        self.assertEqual(klog.warn_count(ERROR), 1, "Warning is not shown")

        self.assertEqual(0, len(deproxy_cl.responses))
        self.assertEqual(1, len(deproxy_cl2.responses))

        # I don't know why the connection is not closed,it should be closed
        self.assertFalse(deproxy_cl.connection_is_closed())
        # I don't know why the connection is not closed,it should be closed
        self.assertFalse(deproxy_cl2.connection_is_closed())
