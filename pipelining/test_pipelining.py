import os

from framework import tester, deproxy_server
from helpers import tf_cfg, deproxy, tempesta, control
from framework.templates import fill_template

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class DeproxyEchoServer(deproxy_server.StaticDeproxyServer):

    def recieve_request(self, request, connection):
        id = request.uri
        r, close = deproxy_server.StaticDeproxyServer.recieve_request(self,
                                                        request, connection)
        resp = deproxy.Response(r)
        resp.body = id
        resp.headers['Content-Length'] = len(resp.body)
        resp.build_message()
        return resp.msg, close

class DeproxyKeepaliveServer(DeproxyEchoServer):

    def __init__(self, *args, **kwargs):
        self.ka = int(kwargs['keep_alive'])
        kwargs.pop('keep_alive', None)
        self.nka = 0
        tf_cfg.dbg(3, "\tDeproxy keepalive: keepalive requests = %i" % self.ka)
        DeproxyEchoServer.__init__(self, *args, **kwargs)

    def run_start(self):
        self.nka = 0
        DeproxyEchoServer.run_start(self)

    def recieve_request(self, request, connection):
        self.nka += 1
        tf_cfg.dbg(5, "\trequests = %i of %i" % (self.nka, self.ka))
        r, close = DeproxyEchoServer.recieve_request(self, request, connection)
        if self.nka < self.ka and not close:
            return r, False
        resp = deproxy.Response(r)
        resp.headers['Connection'] = "close"
        resp.build_message()
        tf_cfg.dbg(3, "\tDeproxy: keepalive closing")
        self.nka = 0
        return resp.msg, True

def build_deproxy_echo(server, name, tester):
    port = server['port']
    if port == 'default':
        port = tempesta.upstream_port_start_from()
    else:
        port = int(port)
    srv = None
    rtype = server['response']
    if rtype == 'static':
        content = fill_template(server['response_content'])
        srv = DeproxyEchoServer(port=port, response=content)
    else:
        raise Exception("Invalid response type: %s" % str(rtype))
    tester.deproxy_manager.add_server(srv)
    return srv

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

tester.register_backend('deproxy_echo', build_deproxy_echo)
tester.register_backend('deproxy_ka', build_deproxy_keepalive)


def build_tempesta_fault(tempesta):
    return control.TempestaFI("resp_alloc_err", True)

tester.register_tempesta('tempesta_fi', build_tempesta_fault)

class PipeliningTest(tester.TempestaTest):

    backends = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy_echo',
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
        # Check that responses goes in the same order as requests

        request = "GET /0 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /1 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /2 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /3 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n"
        deproxy_srv = self.get_server('deproxy')
        deproxy_srv.start()
        self.assertEqual(0, len(deproxy_srv.requests))
        self.start_tempesta()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))
        deproxy_cl = self.get_client('deproxy')
        deproxy_cl.start()
        deproxy_cl.make_requests(request)
        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(resp, "Response not received")
        self.assertEqual(4, len(deproxy_cl.responses))
        self.assertEqual(4, len(deproxy_srv.requests))
        for i in range(len(deproxy_cl.responses)):
            tf_cfg.dbg(3, "Resp %i: %s" % (i, deproxy_cl.responses[i].msg))

        for i in range(len(deproxy_cl.responses)):
            self.assertEqual(deproxy_cl.responses[i].body, "/" + str(i))

    def test_2_pipelined(self):
        # Check that responses goes in the same order as requests
        request = "GET /0 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /1 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /2 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /3 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n"
        request2 = "GET /4 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /5 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n"
        deproxy_srv = self.get_server('deproxy')
        deproxy_srv.start()
        self.assertEqual(0, len(deproxy_srv.requests))
        self.start_tempesta()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))
        deproxy_cl = self.get_client('deproxy')
        deproxy_cl.start()
        deproxy_cl.make_requests(request)
        resp = deproxy_cl.wait_for_response(timeout=5)
        deproxy_cl.make_requests(request2)
        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(resp, "Response not received")
        self.assertEqual(6, len(deproxy_cl.responses))
        self.assertEqual(6, len(deproxy_srv.requests))
        for i in range(len(deproxy_cl.responses)):
            tf_cfg.dbg(3, "Resp %i: %s" % (i, deproxy_cl.responses[i].msg))

        for i in range(len(deproxy_cl.responses)):
            self.assertEqual(deproxy_cl.responses[i].body, "/" + str(i))

    def test_failovering(self):
        # Check that responses goes in the same order as requests
        # This test differs from previous ones in server: it closes connections
        # every 4 requests
        request = "GET /0 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /1 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /2 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /3 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /4 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /5 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /6 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n"
        deproxy_srv = self.get_server('deproxy_ka')
        deproxy_srv.start()
        self.assertEqual(0, len(deproxy_srv.requests))
        self.start_tempesta()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))
        deproxy_cl = self.get_client('deproxy')
        deproxy_cl.start()
        deproxy_cl.make_requests(request)
        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(resp, "Response not received")
        self.assertEqual(7, len(deproxy_cl.responses))
        self.assertEqual(7, len(deproxy_srv.requests))
        for i in range(len(deproxy_cl.responses)):
            tf_cfg.dbg(3, "Resp %i: %s" % (i, deproxy_cl.responses[i].msg))

        for i in range(len(deproxy_cl.responses)):
            self.assertEqual(deproxy_cl.responses[i].body, "/" + str(i))

class PipeliningTestFI(tester.TempestaTest):

    backends = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy_echo',
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
        'type' : "tempesta_fi",
        'config' : """
cache 0;
listen 80;
nonidempotent GET prefix "/";

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
        # Check that responses goes in the same order as requests
        request = "GET /0 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /1 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /2 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /3 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n"
        deproxy_srv = self.get_server('deproxy')
        deproxy_srv.start()
        self.assertEqual(0, len(deproxy_srv.requests))
        self.start_tempesta()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))
        deproxy_cl = self.get_client('deproxy')
        deproxy_cl.start()
        deproxy_cl.make_requests(request)
        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(resp, "Response not received")
        self.assertEqual(4, len(deproxy_cl.responses))
        self.assertEqual(4, len(deproxy_srv.requests))
        for i in range(len(deproxy_cl.responses)):
            tf_cfg.dbg(3, "Resp %i: %s" % (i, deproxy_cl.responses[i].msg))

        for i in range(len(deproxy_cl.responses)):
            self.assertEqual(deproxy_cl.responses[i].body, "/" + str(i))


    def test_failovering(self):
        # Check that responses goes in the same order as requests
        # This test differs from previous one in server: it closes connections
        # every 4 requests
        request = "GET /0 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /1 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /2 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /3 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /4 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /5 HTTP/1.1\r\n" \
                  "Host: localhost\r\n" \
                  "\r\n" \
                  "GET /6 HTTP/1.1\r\n" \
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
        for i in range(len(deproxy_cl.responses)):
            tf_cfg.dbg(3, "Resp %i: %s" % (i, deproxy_cl.responses[i].msg))

        for i in range(len(deproxy_cl.responses)):
            self.assertEqual(deproxy_cl.responses[i].body, "/" + str(i))
