from framework import tester
from helpers import tf_cfg, deproxy

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

resp_keep_alive = """HTTP/1.1 200 OK
Content-Length: 0
Connection: keep-alive

"""

resp_close = """HTTP/1.1 200 OK
Content-Length: 0
Connection: close

"""

class PipeliningTest(tester.TempestaTest):

    backends = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' : resp_keep_alive
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

    def test_pipelined(self):
        request = "GET / HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /path HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /uri HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /app HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n"
        deproxy_srv = self.get_server('deproxy')
        deproxy_srv.start()
        self.assertEqual(0, len(deproxy_srv.requests))
        self.start_tempesta()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))
        deproxy_cl = self.get_client('deproxy')
        deproxy_cl.start()
        deproxy_cl.make_request(request)
        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(resp, "Response not received")
        self.assertEqual(4, len(deproxy_cl.responses))
        self.assertEqual(4, len(deproxy_srv.requests))
        for i in range(len(deproxy_srv.requests)):
            tf_cfg.dbg(3, "Req %i: %s" % (i, deproxy_srv.requests[i].msg))

        self.assertEqual(deproxy_srv.requests[0].uri, "/")
        self.assertEqual(deproxy_srv.requests[1].uri, "/path")
        self.assertEqual(deproxy_srv.requests[2].uri, "/uri")
        self.assertEqual(deproxy_srv.requests[3].uri, "/app")

    def test_2_pipelined(self):
        request = "GET / HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /path HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /uri HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /app HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n"
        request2 = "GET /pre_last HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /last HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n"
        deproxy_srv = self.get_server('deproxy')
        deproxy_srv.start()
        self.assertEqual(0, len(deproxy_srv.requests))
        self.start_tempesta()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))
        deproxy_cl = self.get_client('deproxy')
        deproxy_cl.start()
        deproxy_cl.make_request(request)
        resp = deproxy_cl.wait_for_response(timeout=5)
        deproxy_cl.make_request(request2)
        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(resp, "Response not received")
        self.assertEqual(6, len(deproxy_cl.responses))
        self.assertEqual(6, len(deproxy_srv.requests))
        for i in range(len(deproxy_srv.requests)):
            tf_cfg.dbg(3, "Req %i: %s" % (i, deproxy_srv.requests[i].msg))

        self.assertEqual(deproxy_srv.requests[0].uri, "/")
        self.assertEqual(deproxy_srv.requests[1].uri, "/path")
        self.assertEqual(deproxy_srv.requests[2].uri, "/uri")
        self.assertEqual(deproxy_srv.requests[3].uri, "/app")
        self.assertEqual(deproxy_srv.requests[4].uri, "/pre_last")
        self.assertEqual(deproxy_srv.requests[5].uri, "/last")

    def test_failovering(self):
        request = "GET / HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /path HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n"
        deproxy_srv = self.get_server('deproxy')
        deproxy_srv.start()
        self.assertEqual(0, len(deproxy_srv.requests))
        self.start_tempesta()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))
        deproxy_cl = self.get_client('deproxy')
        deproxy_cl.start()
        deproxy_cl.make_request(request)
        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(resp, "Response not received")
        self.assertEqual(2, len(deproxy_cl.responses))
        self.assertEqual(2, len(deproxy_srv.requests))
        self.assertEqual(deproxy_srv.requests[0].uri, "/")
        self.assertEqual(deproxy_srv.requests[1].uri, "/path")
