import os

from framework import deproxy_server, tester
from framework.templates import fill_template
from helpers import control, deproxy, tempesta, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"


class DeproxyEchoServer(deproxy_server.StaticDeproxyServer):
    def receive_request(self, request):
        id = request.uri
        r, close = deproxy_server.StaticDeproxyServer.receive_request(self, request)
        resp = deproxy.Response(r)
        resp.body = id
        resp.headers["Content-Length"] = len(resp.body)
        resp.build_message()
        return resp.msg, close


class DeproxyKeepaliveServer(DeproxyEchoServer):
    def __init__(self, *args, **kwargs):
        self.ka = int(kwargs["keep_alive"])
        kwargs.pop("keep_alive", None)
        self.nka = 0
        tf_cfg.dbg(3, "\tDeproxy keepalive: keepalive requests = %i" % self.ka)
        DeproxyEchoServer.__init__(self, *args, **kwargs)

    def run_start(self):
        self.nka = 0
        DeproxyEchoServer.run_start(self)

    def receive_request(self, request):
        self.nka += 1
        tf_cfg.dbg(5, "\trequests = %i of %i" % (self.nka, self.ka))
        r, close = DeproxyEchoServer.receive_request(self, request)
        if self.nka < self.ka and not close:
            return r, False
        resp = deproxy.Response(r)
        resp.headers["Connection"] = "close"
        resp.build_message()
        tf_cfg.dbg(3, "\tDeproxy: keepalive closing")
        self.nka = 0
        return resp.msg, True


def build_deproxy_echo(server, name, tester):
    port = server["port"]
    if port == "default":
        port = tempesta.upstream_port_start_from()
    else:
        port = int(port)
    srv = None
    rtype = server["response"]
    if rtype == "static":
        content = fill_template(server["response_content"], server)
        srv = DeproxyEchoServer(port=port, response=content)
    else:
        raise Exception("Invalid response type: %s" % str(rtype))
    tester.deproxy_manager.add_server(srv)
    return srv


def build_deproxy_keepalive(server, name, tester):
    port = server["port"]
    if port == "default":
        port = tempesta.upstream_port_start_from()
    else:
        port = int(port)
    srv = None
    rtype = server["response"]
    ka = server["keep_alive"]
    if rtype == "static":
        content = fill_template(server["response_content"], server)
        srv = DeproxyKeepaliveServer(port=port, response=content, keep_alive=ka)
    else:
        raise Exception("Invalid response type: %s" % str(rtype))
    tester.deproxy_manager.add_server(srv)
    return srv


tester.register_backend("deproxy_echo", build_deproxy_echo)
tester.register_backend("deproxy_ka", build_deproxy_keepalive)


def build_tempesta_fault(tempesta):
    return control.TempestaFI("resp_alloc_err", True)


tester.register_tempesta("tempesta_fi", build_tempesta_fault)


class PipeliningTest(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy_echo",
            "port": "8000",
            "response": "static",
            "response_content": """HTTP/1.1 200 OK
Content-Length: 0
Connection: keep-alive

""",
        },
        {
            "id": "deproxy_ka",
            "type": "deproxy_ka",
            "keep_alive": 4,
            "port": "8000",
            "response": "static",
            "response_content": """HTTP/1.1 200 OK
Content-Length: 0
Connection: keep-alive

""",
        },
    ]

    tempesta = {
        "config": """
cache 0;
server ${general_ip}:8000;

""",
    }

    clients = [
        {"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"},
    ]

    def test_pipelined(self):
        # Check that responses goes in the same order as requests

        request = (
            "GET /0 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            "GET /1 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            "GET /2 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            "GET /3 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
        )
        deproxy_srv = self.get_server("deproxy")
        deproxy_srv.start()
        self.assertEqual(0, len(deproxy_srv.requests))
        self.start_tempesta()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.start()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))
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
        request = (
            "GET /0 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            "GET /1 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            "GET /2 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            "GET /3 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
        )
        request2 = (
            "GET /4 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            "GET /5 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
        )
        deproxy_srv = self.get_server("deproxy")
        deproxy_srv.start()
        self.assertEqual(0, len(deproxy_srv.requests))
        self.start_tempesta()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.start()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))
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
        request = (
            "GET /0 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            "GET /1 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            "GET /2 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            "GET /3 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            "GET /4 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            "GET /5 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            "GET /6 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
        )
        deproxy_srv = self.get_server("deproxy_ka")
        deproxy_srv.start()
        self.assertEqual(0, len(deproxy_srv.requests))
        self.start_tempesta()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.start()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))
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
            "id": "deproxy",
            "type": "deproxy_echo",
            "port": "8000",
            "response": "static",
            "response_content": """HTTP/1.1 200 OK
Content-Length: 0
Connection: keep-alive

""",
        },
        {
            "id": "deproxy_ka",
            "type": "deproxy_ka",
            "keep_alive": 4,
            "port": "8000",
            "response": "static",
            "response_content": """HTTP/1.1 200 OK
Content-Length: 0
Connection: keep-alive

""",
        },
    ]

    tempesta = {
        "type": "tempesta_fi",
        "config": """
cache 0;
nonidempotent GET prefix "/";

server ${general_ip}:8000;

""",
    }

    clients = [
        {"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"},
    ]

    def test_pipelined(self):
        # Check that responses goes in the same order as requests
        request = (
            "GET /0 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            "GET /1 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            "GET /2 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            "GET /3 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
        )
        deproxy_srv = self.get_server("deproxy")
        deproxy_srv.start()
        self.assertEqual(0, len(deproxy_srv.requests))
        self.start_tempesta()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.start()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))
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
        request = (
            "GET /0 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            "GET /1 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            "GET /2 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            "GET /3 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            "GET /4 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            "GET /5 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
            "GET /6 HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "\r\n"
        )
        deproxy_srv = self.get_server("deproxy_ka")
        deproxy_srv.start()
        self.assertEqual(0, len(deproxy_srv.requests))
        self.start_tempesta()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.start()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))
        deproxy_cl.make_request(request)
        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(resp, "Response not received")
        self.assertEqual(7, len(deproxy_cl.responses))
        self.assertEqual(7, len(deproxy_srv.requests))
        for i in range(len(deproxy_cl.responses)):
            tf_cfg.dbg(3, "Resp %i: %s" % (i, deproxy_cl.responses[i].msg))

        for i in range(len(deproxy_cl.responses)):
            self.assertEqual(deproxy_cl.responses[i].body, "/" + str(i))


class H2MultiplexedTest(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        }
    ]

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "localhost",
        },
    ]

    tempesta = {
        "config": """
        listen 443 proto=h2;
        server ${server_ip}:8000;

        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;

        tls_match_any_server_name;

        """
    }

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.start_all_clients()
        self.assertTrue(self.wait_all_connections())

    def test_bodyless(self):
        self.start_all()

        REQ_NUM = 10
        head = [
            (":authority", "localhost"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "GET"),
        ]

        request = []
        for i in range(REQ_NUM):
            request.append(head)

        deproxy_srv = self.get_server("deproxy")
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.make_requests(request)

        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertEqual(REQ_NUM, len(deproxy_cl.responses))
        self.assertEqual(REQ_NUM, len(deproxy_srv.requests))

        for response in deproxy_cl.responses:
            self.assertEqual(200, int(response.status))
