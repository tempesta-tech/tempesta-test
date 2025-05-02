import typing

from framework import deproxy_server
from helpers import control, deproxy, tf_cfg
from test_suite import marks, tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

REQUESTS_EXECUTION_SEQUENCE = []


class DeproxyEchoServer(deproxy_server.StaticDeproxyServer):
    def receive_request(self, request) -> (bytes, bool):
        id = request.uri
        r, close = deproxy_server.StaticDeproxyServer.receive_request(self, request)
        resp = deproxy.Response(r.decode())
        resp.body = id
        resp.headers["Content-Length"] = len(resp.body)
        resp.build_message()
        return resp.msg.encode(), close


class DeproxyKeepaliveServer(DeproxyEchoServer):
    def __init__(self, *args, **kwargs):
        self.ka = int(kwargs["keep_alive"])
        kwargs.pop("keep_alive", None)
        self.nka = 0
        tf_cfg.dbg(3, "\tDeproxy keepalive: keepalive requests = %i" % self.ka)
        DeproxyEchoServer.__init__(self, *args, **kwargs)

    def run_start(self):
        self.nka = 0
        super().run_start()

    def receive_request(self, request) -> (bytes, bool):
        self.nka += 1
        tf_cfg.dbg(5, "\trequests = %i of %i" % (self.nka, self.ka))
        r, close = super().receive_request(request)
        if self.nka < self.ka and not close:
            return r, False
        resp = deproxy.Response(r.decode())
        resp.headers["Connection"] = "close"
        resp.build_message()
        tf_cfg.dbg(3, "\tDeproxy: keepalive closing")
        self.nka = 0
        return resp.msg.encode(), True


class DeproxyRegisterRequestsExecutingSequenceServer(DeproxyEchoServer):
    def __init__(self, *args, **kwargs):
        super(DeproxyRegisterRequestsExecutingSequenceServer, self).__init__(*args, **kwargs)

    def receive_request(self, request) -> (bytes, bool):
        req_num = request.uri.split("/")[-1]
        REQUESTS_EXECUTION_SEQUENCE.append(req_num)

        r, close = super().receive_request(request)
        resp = deproxy.Response(r.decode())
        resp.body = "".join(REQUESTS_EXECUTION_SEQUENCE)
        resp.headers["seq"] = req_num
        resp.headers["Content-Length"] = len(resp.body)
        resp.build_message()
        return resp.msg.encode(), close


def build_server(
    deproxy_server_class: DeproxyEchoServer, keep_alive: bool = False
) -> typing.Callable:
    def builder(server, name, tester):
        return deproxy_server.deproxy_srv_initializer(
            server, name, tester, default_server_class=deproxy_server_class
        )

    return builder


tester.register_backend("deproxy_echo", build_server(DeproxyEchoServer))
tester.register_backend("deproxy_ka", build_server(DeproxyKeepaliveServer))
tester.register_backend("deproxy_ex", build_server(DeproxyRegisterRequestsExecutingSequenceServer))


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
server ${server_ip}:8000;

""",
    }

    clients = [
        {"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"},
    ]

    def test_pipelined(self):
        # Check that responses goes in the same order as requests

        request = [
            "GET /0 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "GET /1 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "GET /2 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "GET /3 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
        ]
        deproxy_srv = self.get_server("deproxy")
        deproxy_srv.start()
        self.assertEqual(0, len(deproxy_srv.requests))
        self.start_tempesta()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.start()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))
        deproxy_cl.make_requests(request, pipelined=True)
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
        request = [
            "GET /0 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "GET /1 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "GET /2 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "GET /3 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
        ]
        request2 = [
            "GET /4 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "GET /5 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
        ]
        deproxy_srv = self.get_server("deproxy")
        deproxy_srv.start()
        self.assertEqual(0, len(deproxy_srv.requests))
        self.start_tempesta()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.start()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))
        deproxy_cl.make_requests(request, pipelined=True)
        resp = deproxy_cl.wait_for_response(timeout=5)
        deproxy_cl.make_requests(request2, pipelined=True)
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
        request = [
            "GET /0 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "GET /1 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "GET /2 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "GET /3 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "GET /4 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "GET /5 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "GET /6 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
        ]
        deproxy_srv = self.get_server("deproxy_ka")
        deproxy_srv.start()
        self.assertEqual(0, len(deproxy_srv.requests))
        self.start_tempesta()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.start()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))
        deproxy_cl.make_requests(request, pipelined=True)
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

server ${server_ip}:8000;

""",
    }

    clients = [
        {"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"},
    ]

    def test_pipelined(self):
        # Check that responses goes in the same order as requests
        request = [
            "GET /0 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "GET /1 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "GET /2 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "GET /3 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
        ]
        deproxy_srv = self.get_server("deproxy")
        deproxy_srv.start()
        self.assertEqual(0, len(deproxy_srv.requests))
        self.start_tempesta()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.start()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))
        deproxy_cl.make_requests(request, pipelined=True)
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
        request = [
            "GET /0 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "GET /1 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "GET /2 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "GET /3 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "GET /4 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "GET /5 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            "GET /6 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
        ]
        deproxy_srv = self.get_server("deproxy_ka")
        deproxy_srv.start()
        self.assertEqual(0, len(deproxy_srv.requests))
        self.start_tempesta()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.start()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))
        deproxy_cl.make_request(request, pipelined=True)
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


@marks.parameterize_class(
    [
        {
            "name": "POST",
            "method": "POST",
        },
        {
            "name": "PUT",
            "method": "PUT",
        },
        {
            "name": "PATCH",
            "method": "PATCH",
        },
    ]
)
class TestPipelinedNonIdempotentRequests(tester.TempestaTest):
    method: str = ""
    backends = [
        {
            "id": "deproxy0",
            "type": "deproxy_ex",
            "port": "8000",
            "response": "static",
            "delay_before_sending_response": 3,
            "response_content": ("HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n" "\r\n\r\n"),
        },
        {
            "id": "deproxy1",
            "type": "deproxy_ex",
            "port": "8001",
            "response": "static",
            "delay_before_sending_response": 2,
            "response_content": ("HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n" "\r\n\r\n"),
        },
        {
            "id": "deproxy2",
            "type": "deproxy_ex",
            "port": "8002",
            "response": "static",
            "delay_before_sending_response": 1,
            "response_content": ("HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n" "\r\n\r\n"),
        },
    ]
    tempesta = {
        "config": """
            listen 80;
            cache 0;
            frang_limits {
               http_strict_host_checking false;
               http_methods GET PUT POST PATCH;
            }

            srv_group sg0 { server ${server_ip}:8000; }
            srv_group sg1 { server ${server_ip}:8001; }
            srv_group sg2 { server ${server_ip}:8002; }

            vhost server0 { proxy_pass sg0; }
            vhost server1 { proxy_pass sg1; }
            vhost server2 { proxy_pass sg2; }

            http_chain {
              uri == "/0" -> server0;
              uri == "/1" -> server1;
              uri == "/2" -> server2;
            }
            """
    }

    clients = [{"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"}]

    @staticmethod
    def __set_method(request: str, method_name: str) -> str:
        return request.format(method=method_name)

    def _test(self, requests: list[str], correct_order: str):
        global REQUESTS_EXECUTION_SEQUENCE

        REQUESTS_EXECUTION_SEQUENCE = []
        __requests = [self.__set_method(request, self.method) for request in requests]

        self.disable_deproxy_auto_parser()
        self.start_all_services()

        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.make_requests(__requests, pipelined=True)
        deproxy_cl.wait_for_response(timeout=5)

        self.assertEqual(3, len(deproxy_cl.responses))

        # check correctness of responses sequence
        response_seq = "".join([response.headers.get("seq") for response in deproxy_cl.responses])
        self.assertEqual(response_seq, correct_order)

        # first non-idempotent request should always started first
        self.assertEqual("".join(REQUESTS_EXECUTION_SEQUENCE), correct_order)

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="first_non_idempotent",
                requests=[
                    "{method} /0 HTTP/1.1\r\nHost: localhost\r\nContent-Length:0\r\n\r\n",
                    "GET /1 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
                    "GET /2 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
                ],
                correct_order="012",
            ),
            marks.Param(
                name="middle_non_idempotent",
                requests=[
                    "GET /1 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
                    "{method} /0 HTTP/1.1\r\nHost: localhost\r\nContent-Length:0\r\n\r\n",
                    "GET /2 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
                ],
                correct_order="102",
            ),
            marks.Param(
                name="last_non_idempotent",
                requests=[
                    "GET /1 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
                    "GET /2 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
                    "{method} /0 HTTP/1.1\r\nHost: localhost\r\nContent-Length:0\r\n\r\n",
                ],
                correct_order="120",
            ),
        ]
    )
    def test_pipelined(self, name: str, requests: list[str], correct_order: str):
        """
        Here we check the response orders and EXECUTING order. The non-idempotent requests should block all further
        idempotent requests.
        """
        self._test(requests, correct_order)


class TestPipelinedNonIdempotentRequestsGET(TestPipelinedNonIdempotentRequests):
    tempesta = {
        "config": """
            listen 80;
            cache 0;
            frang_limits {
               http_strict_host_checking false;
            }

            srv_group sg0 { server ${server_ip}:8000; }
            srv_group sg1 { server ${server_ip}:8001; }
            srv_group sg2 { server ${server_ip}:8002; }

            vhost server0 { proxy_pass sg0; }
            vhost server1 { proxy_pass sg1; }
            vhost server2 { proxy_pass sg2; }
            
            nonidempotent GET prefix "/0";
            
            http_chain {
              uri == "/0" -> server0;
              uri == "/1" -> server1;
              uri == "/2" -> server2;
            }
            """
    }

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="first_non_idempotent",
                requests=[
                    "GET /0 HTTP/1.1\r\nHost: localhost\r\nContent-Length:0\r\n\r\n",
                    "GET /1 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
                    "GET /2 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
                ],
                correct_order="012",
            ),
            marks.Param(
                name="middle_non_idempotent",
                requests=[
                    "GET /1 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
                    "GET /0 HTTP/1.1\r\nHost: localhost\r\nContent-Length:0\r\n\r\n",
                    "GET /2 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
                ],
                correct_order="102",
            ),
            marks.Param(
                name="last_non_idempotent",
                requests=[
                    "GET /1 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
                    "GET /2 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
                    "GET /0 HTTP/1.1\r\nHost: localhost\r\nContent-Length:0\r\n\r\n",
                ],
                correct_order="120",
            ),
        ]
    )
    def test_pipelined(self, name: str, requests: list[str], correct_order: str):
        self._test(requests, correct_order)


class TestPipelinedNonIdempotentRequestsH2GET(TestPipelinedNonIdempotentRequests):
    tempesta = {
        "config": """
            listen 443 proto=https,h2;
            
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;
        
            cache 0;
            frang_limits {
               http_strict_host_checking false;
            }

            srv_group sg0 { server ${server_ip}:8000; }
            srv_group sg1 { server ${server_ip}:8001; }
            srv_group sg2 { server ${server_ip}:8002; }

            vhost server0 { proxy_pass sg0; }
            vhost server1 { proxy_pass sg1; }
            vhost server2 { proxy_pass sg2; }

            nonidempotent GET prefix "/0";

            http_chain {
              uri == "/0" -> server0;
              uri == "/1" -> server1;
              uri == "/2" -> server2;
            }
            """
    }
    clients = [
        {"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "443", "ssl": True}
    ]

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="first_non_idempotent",
                requests=[
                    "GET /0 HTTP/1.1\r\nHost: localhost\r\nContent-Length:0\r\n\r\n",
                    "GET /1 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
                    "GET /2 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
                ],
                correct_order="012",
            ),
            marks.Param(
                name="middle_non_idempotent",
                requests=[
                    "GET /1 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
                    "GET /0 HTTP/1.1\r\nHost: localhost\r\nContent-Length:0\r\n\r\n",
                    "GET /2 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
                ],
                correct_order="102",
            ),
            marks.Param(
                name="last_non_idempotent",
                requests=[
                    "GET /1 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
                    "GET /2 HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
                    "GET /0 HTTP/1.1\r\nHost: localhost\r\nContent-Length:0\r\n\r\n",
                ],
                correct_order="120",
            ),
        ]
    )
    def test_pipelined(self, name: str, requests: list[str], correct_order: str):
        self._test(requests, correct_order)
