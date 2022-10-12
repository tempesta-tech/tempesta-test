from helpers import dmesg
from t_frang.frang_test_case import FrangTestCase

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'
ERROR = "Warning: frang: HTTP header chunk count exceeded"


class HttpHeaderChunkCntBase(FrangTestCase):

    clients = [
        {
            'id': 'deproxy',
            'type': 'deproxy',
            'addr': "${tempesta_ip}",
            'port': '80',
            'interface': True,
            'segment_size': 1,
            'segment_gap': 100
        },
        {
            'id': 'deproxy2',
            'type': 'deproxy',
            'addr': "${tempesta_ip}",
            'port': '80',
            'interface': True,
            'segment_size': 0
        },
        {
            'id': 'deproxy3',
            'type': 'deproxy',
            'addr': "${tempesta_ip}",
            'port': '80',
            'segment_size': 1,
            'segment_gap': 100
        },
        {
            'id': 'deproxy4',
            'type': 'deproxy',
            'addr': "${tempesta_ip}",
            'port': '80',
            'rps': 5
        }
    ]


class HttpHeaderChunkCnt(HttpHeaderChunkCntBase):
    tempesta = {
        'config': """
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
        self.assertEqual(
            klog.warn_count(ERROR),
            1,
            "Frang limits warning is not shown"
            )

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
        self.assertEqual(
            klog.warn_count(ERROR),
            1,
            "Frang limits warning is not shown"
            )

        self.assertEqual(0, len(deproxy_cl.responses))
        self.assertEqual(1, len(deproxy_cl2.responses))

        self.assertFalse(deproxy_cl.connection_is_closed())
        self.assertFalse(deproxy_cl2.connection_is_closed())
