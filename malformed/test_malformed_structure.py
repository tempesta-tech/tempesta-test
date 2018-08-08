from framework import tester
from helpers import tf_cfg, deproxy

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class MalformedStructureTest(tester.TempestaTest):
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

    def common_check(self, request, expect=400):
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

    def test_lfcr(self):
        request = 'GET / HTTP/1.1\n\r' \
                  'Host: localhost\n\r' \
                  '\n\r'
        self.common_check(request, 400)

    def test_space(self):
        # https://tools.ietf.org/html/rfc7230#section-3.2.4
        request = 'GET / HTTP/1.1\r\n' \
                  'Host : localhost\r\n' \
                  '\r\n'
        expect = 'GET / HTTP/1.1\r\n' \
                  'Host: localhost\r\n' \
                  '\r\n'

        deproxy_srv = self.get_server('deproxy')
        deproxy_srv.start()
        self.start_tempesta()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))
        deproxy_cl = self.get_client('deproxy')
        deproxy_cl.start()
        deproxy_cl.make_request(request)
        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(resp, "Response not received")
        status = int(deproxy_cl.last_response.status)
        self.assertTrue(status == 200 or status == 400)
        if status == 200:
            self.assertEqual(deproxy_srv.last_request, expect)
