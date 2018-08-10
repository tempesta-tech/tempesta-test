from framework import tester, deproxy_server
from helpers import tf_cfg, deproxy, tempesta
from framework.templates import fill_template

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class DeproxyKeepaliveServer(deproxy_server.StaticDeproxyServer):

    def __init__(self, *args, **kwargs):
        self.ka = int(kwargs['keep_alive'])
        kwargs.pop('keep_alive', None)
        self.nka = 0
        tf_cfg.dbg(3, "\tDeproxy keepalive: keepalive requests = %i" % self.ka)
        deproxy_server.StaticDeproxyServer.__init__(self, *args, **kwargs)

    def run_start(self):
        self.nka = 0
        deproxy_server.StaticDeproxyServer.run_start(self)

    def recieve_request(self, request, connection):
        self.requests.append(request)
        self.last_request = request
        self.nka += 1
        tf_cfg.dbg(5, "\trequests = %i of %i" % (self.nka, self.ka))
        if self.nka < self.ka:
            return self.response, False
        resp = deproxy.Response(self.response)
        resp.headers['Connection'] = "close"
        resp.build_message()
        tf_cfg.dbg(3, "\tDeproxy: keepalive closing")
        self.nka = 0
        return resp.msg, True

def build_deproxy_keepalive(server, name, tester):
    port = server['port']
    if port == 'default':
        port = tempesta.upstream_port_start_from()
    else:
        port = int(port)
    srv = None
    rtype = server['response']
    ka = server['keep_alive']
    if rtype == 'static':
        content = fill_template(server['response_content'])
        srv = DeproxyKeepaliveServer(port=port,
                                     response=content,
                                     keep_alive=ka)
    else:
        raise Exception("Invalid response type: %s" % str(rtype))
    tester.deproxy_manager.add_server(srv)
    return srv

tester.register_backend('deproxy_ka', build_deproxy_keepalive)

class PipeliningTest(tester.TempestaTest):

    backends = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' : """HTTP/1.1 200 OK
Content-Length: 0
Connection: keep-alive

"""
        },
        {
            'id' : 'deproxy_ka',
            'type' : 'deproxy_ka',
            'keep_alive' : 4,
            'port' : '8000',
            'response' : 'static',
            'response_content' : """HTTP/1.1 200 OK
Content-Length: 0
Connection: keep-alive

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
                  "GET /path1 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /path2 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /path3 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /path4 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /path5 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /path6 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n"
        deproxy_srv = self.get_server('deproxy_ka')
        deproxy_srv.start()
        self.assertEqual(0, len(deproxy_srv.requests))
        self.start_tempesta()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))
        deproxy_cl = self.get_client('deproxy')
        deproxy_cl.start()
        deproxy_cl.make_request(request)
        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(resp, "Response not received")
        self.assertEqual(7, len(deproxy_cl.responses))
        self.assertEqual(7, len(deproxy_srv.requests))
        for i in range(len(deproxy_srv.requests)):
            tf_cfg.dbg(3, "Req %i: %s" % (i, deproxy_srv.requests[i].msg))
        self.assertEqual(deproxy_srv.requests[0].uri, "/")
        self.assertEqual(deproxy_srv.requests[1].uri, "/path1")
        self.assertEqual(deproxy_srv.requests[2].uri, "/path2")
        self.assertEqual(deproxy_srv.requests[3].uri, "/path3")
        self.assertEqual(deproxy_srv.requests[4].uri, "/path4")
        self.assertEqual(deproxy_srv.requests[5].uri, "/path5")
        self.assertEqual(deproxy_srv.requests[6].uri, "/path6")
