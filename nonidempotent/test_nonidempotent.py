from framework import deproxy, deproxy_server
from helpers import tf_cfg
from helpers.util import fill_template
from test_suite import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework.deproxy import HttpMessage

NGINX_CONFIG = """
load_module /usr/lib/nginx/modules/ngx_http_echo_module.so;
pid ${pid};
worker_processes  auto;

events {
    worker_connections   512;
    use epoll;
}

http {
    keepalive_timeout ${server_keepalive_timeout};
    keepalive_requests ${server_keepalive_requests};
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

        location / {
            return 200;
        }

        location /nip/ {
            echo_sleep 3.0;
            echo_exec @default;
        }

        location @default {
            return 200;
        }

        location /nginx_status {
            stub_status on;
        }

        add_header X-Upstream-Id 1 always;
    }

    server {
        listen       ${server_ip}:8001;

        location / {
            return 200;
        }

        location /nip/ {
            echo_sleep 3.0;
            echo_exec @default;
        }

        location @default {
            return 200;
        }

        location /nginx_status {
            stub_status on;
        }

        add_header X-Upstream-Id 2;
    }
}
"""


class DeproxyDropServer(deproxy_server.StaticDeproxyServer):
    """
    Simply drops one request which contains '/drop/' part in URI.
    """

    do_drop = True

    def receive_request(self, request):
        uri = request.uri
        r, close = deproxy_server.StaticDeproxyServer.receive_request(self, request)
        if "/drop/" in uri and self.do_drop:
            self.do_drop = False
            return "", True

        resp = deproxy.Response(r.decode())
        return resp.msg.encode(), close


def build_deproxy_drop(server, name, tester):
    is_ipv6 = server.get("is_ipv6", False)
    srv = DeproxyDropServer(
        # BaseDeproxy
        id_=name,
        deproxy_auto_parser=tester._deproxy_auto_parser,
        port=int(server["port"]),
        bind_addr=tf_cfg.cfg.get("Server", "ipv6" if is_ipv6 else "ip"),
        segment_size=server.get("segment_size", 0),
        segment_gap=server.get("segment_gap", 0),
        is_ipv6=is_ipv6,
        # StaticDeproxyServer
        response=fill_template(server.get("response_content", ""), server),
        keep_alive=server.get("keep_alive", 0),
        drop_conn_when_request_received=server.get("drop_conn_when_request_received", False),
        send_after_conn_established=server.get("send_after_conn_established", False),
        delay_before_sending_response=server.get("delay_before_sending_response", 0.0),
        hang_on_req_num=server.get("hang_on_req_num", 0),
        pipelined=server.get("pipelined", 0),
    )
    tester.deproxy_manager.add_server(srv)
    return srv


tester.register_backend("deproxy_drop", build_deproxy_drop)


class NonIdempotentH2TestBase(tester.TempestaTest, base=True):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "localhost",
        }
    ]

    requests = []

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.deproxy_manager.start()

    def send_requests(self, req_params, client):
        requests = []
        headers = [(":authority", "localhost"), (":scheme", "https")]

        for path, method in req_params:
            req_headers = headers.copy()
            req_headers.append((":method", method))
            req_headers.append((":path", path))
            if method == "POST":
                req_headers.append(("content-length", "0"))
            requests.append(req_headers)

        client.make_requests(requests)


class NonIdempotentH2SchedTest(NonIdempotentH2TestBase):
    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "req_id": "$request_uri",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG,
        }
    ]

    tempesta = {
        "config": """
        listen 443 proto=h2;
        server ${server_ip}:8000 conns_n=1 weight=10;
        server ${server_ip}:8001 conns_n=1 weight=9;

        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;

        cache 0;
        nonidempotent GET prefix "/nip/";
        sched ratio static;
        """
    }

    requests = [("/nip/", "GET"), ("/regular/", "GET")]

    def test(self):
        """
        In this test we send one request with two streams, one of these requests
        is non-idempotent and must be processed with a couple of seconds delay.
        Each request must be forwarded to separate upstream. If both requests
        will be in the same upstream is an error.
        """
        self.start_all()

        deproxy_cl = self.get_client("deproxy")

        self.send_requests(self.requests, deproxy_cl)
        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(resp, "Response not received")
        self.assertEqual(2, len(deproxy_cl.responses))

        first, second = deproxy_cl.responses
        first_upstream = first.headers.get("X-Upstream-Id")
        second_upstream = second.headers.get("X-Upstream-Id")
        self.assertNotEqual(first_upstream, second_upstream)


class RetryNonIdempotentH2Test(NonIdempotentH2TestBase):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy_drop",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "Content-Type: text/html\r\n"
            f"Date: {deproxy.HttpMessage.date_time_string()}\r\n"
            "Server: deproxy\r\n\r\n",
        }
    ]

    tempesta = {
        "config": """
        listen 443 proto=h2;
        server ${server_ip}:8000;

        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;

        cache 0;
        nonidempotent GET prefix "/nip/";
        server_retry_nonidempotent;
        """
    }

    requests = [("/nip/drop/", "GET"), ("/regular/", "GET")]

    def start_all(self):
        NonIdempotentH2TestBase.start_all(self)
        self.assertTrue(self.wait_all_connections())

    def test(self):
        self.disable_deproxy_auto_parser()
        self.start_all()

        deproxy_cl = self.get_client("deproxy")
        self.send_requests(self.requests, deproxy_cl)
        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(resp, "Response not received")
        self.assertEqual(2, len(deproxy_cl.responses))

        for response in deproxy_cl.responses:
            self.assertEqual(int(response.status), 200)


class RetryNonIdempotentPostH2Test(RetryNonIdempotentH2Test):
    requests = [("/myform/drop/", "POST"), ("/regular/", "GET")]


class NotRetryNonIdempotentH2Test(NonIdempotentH2TestBase):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy_drop",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "Content-Type: text/html\r\n"
            f"Date: {HttpMessage.date_time_string()}\r\n"
            "Server: deproxy\r\n\r\n",
        }
    ]

    tempesta = {
        "config": """
        listen 443 proto=h2;
        server ${server_ip}:8000;

        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;

        cache 0;
        nonidempotent GET prefix "/nip/";
        """
    }

    requests = [("/nip/drop/", "GET"), ("/regular/", "GET")]

    def start_all(self):
        NonIdempotentH2TestBase.start_all(self)
        self.assertTrue(self.wait_all_connections())

    def test(self):
        self.disable_deproxy_auto_parser()
        self.start_all()

        deproxy_cl = self.get_client("deproxy")
        self.send_requests(self.requests, deproxy_cl)
        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(resp, "Response not received")
        self.assertEqual(2, len(deproxy_cl.responses))

        statuses = []
        for response in deproxy_cl.responses:
            statuses.append(int(response.status))
        self.assertTrue(all(s in statuses for s in [200, 504]), "200 and 504 must present")


class NotRetryNonIdempotentPostH2Test(NotRetryNonIdempotentH2Test):
    requests = [("/myform/drop/", "POST"), ("/regular/", "GET")]


class NonIdempotentH1TestBase(tester.TempestaTest, base=True):
    clients = [{"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"}]

    requests = ""

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.deproxy_manager.start()


class NonIdempotentH1SchedTest(NonIdempotentH1TestBase):
    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "req_id": "$request_uri",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG,
        }
    ]

    tempesta = {
        "config": """
        listen 80;
        server ${server_ip}:8000 conns_n=1 weight=10;
        server ${server_ip}:8001 conns_n=1 weight=9;

        cache 0;
        nonidempotent GET prefix "/nip/";
        sched ratio static;
        """
    }

    requests = [
        "GET /nip/ HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "GET /regular/ HTTP/1.1\r\nHost: localhost\r\n\r\n",
    ]

    def test(self):
        """
        In this test we send two pipelined requests, one of these requests
        is non-idempotent and must be processed with a couple of seconds delay.
        Each request must be forwarded to separate upstream. If both requests
        will be in the same upstream is an error.
        """
        self.start_all()

        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.make_requests(self.requests, pipelined=True)
        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(resp, "Response not received")
        self.assertEqual(2, len(deproxy_cl.responses))

        first, second = deproxy_cl.responses
        first_upstream = first.headers.get("X-Upstream-Id")
        second_upstream = second.headers.get("X-Upstream-Id")
        self.assertNotEqual(first_upstream, second_upstream)


class RetryNonIdempotentH1Test(NonIdempotentH1TestBase):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy_drop",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "Content-Type: text/html\r\n"
            f"Date: {HttpMessage.date_time_string()}\r\n"
            "Server: deproxy\r\n\r\n",
        }
    ]

    tempesta = {
        "config": """
        listen 80;
        server ${server_ip}:8000;

        cache 0;
        nonidempotent GET prefix "/nip/";
        """
    }

    requests = [
        "GET /nip/ HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "GET /regular/ HTTP/1.1\r\nHost: localhost\r\n\r\n",
    ]

    def start_all(self):
        NonIdempotentH1TestBase.start_all(self)
        self.assertTrue(self.wait_all_connections())

    def test(self):
        """
        This test has difference from HTTP2 version. Non-idempotent request
        will be turned into regular request, because non-idempotent followed
        by another request. See RFC 7230 6.3.2.
        """
        self.disable_deproxy_auto_parser()
        self.start_all()

        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.make_requests(self.requests)
        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(resp, "Response not received")
        self.assertEqual(2, len(deproxy_cl.responses))

        for response in deproxy_cl.responses:
            self.assertEqual(int(response.status), 200)


class RetryNonIdempotentPostH1Test(RetryNonIdempotentH1Test):
    requests = [
        "POST /nonidem/drop/ HTTP/1.1\r\ncontent-length: 0\r\nHost: localhost\r\n\r\n",
        "GET /regular/ HTTP/1.1\r\nHost: localhost\r\n\r\n",
    ]


class RetryNonIdempotenRevOrderH1Test(RetryNonIdempotentH1Test):
    tempesta = {
        "config": """
        listen 80;
        server ${server_ip}:8000;

        cache 0;
        nonidempotent GET prefix "/nip/";
        server_retry_nonidempotent;
        """
    }

    requests = [
        "GET /regular/ HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "GET /nip/drop/ HTTP/1.1\r\nHost: localhost\r\n\r\n",
    ]


class NotRetryNonIdempotentH1Test(NonIdempotentH1TestBase):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy_drop",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Content-Length: 0\r\n"
            "Content-Type: text/html\r\n"
            f"Date: {HttpMessage.date_time_string()}\r\n"
            "Server: deproxy\r\n\r\n",
        }
    ]

    tempesta = {
        "config": """
        listen 80;
        server ${server_ip}:8000;
        nonidempotent GET prefix "/nip/";
        cache 0;
        """
    }

    requests = [
        "GET /regular/ HTTP/1.1\r\nHost: localhost\r\n\r\n",
        "GET /nip/drop/ HTTP/1.1\r\nHost: localhost\r\n\r\n",
    ]

    def start_all(self):
        NonIdempotentH1TestBase.start_all(self)
        self.assertTrue(self.wait_all_connections())

    def test(self):
        self.disable_deproxy_auto_parser()
        self.start_all()

        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.make_requests(self.requests)
        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(resp, "Response not received")
        self.assertEqual(2, len(deproxy_cl.responses))

        statuses = []
        for response in deproxy_cl.responses:
            statuses.append(int(response.status))
        self.assertTrue(all(s in statuses for s in [200, 504]), "200 and 504 must present")
