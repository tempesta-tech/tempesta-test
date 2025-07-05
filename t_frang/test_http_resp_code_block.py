"""
Functional tests for http_resp_code_block.
If your web application works with user accounts, then typically it requires
a user authentication. If you implement the user authentication on your web
site, then an attacker may try to use a brute-force password cracker to get
access to accounts of your users. The second case is much harder to detect.
It's worth mentioning that unsuccessful authorization requests typically
produce error HTTP responses.

Tempesta FW provides http_resp_code_block for efficient blocking
of all types of password crackers
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from t_frang.frang_test_case import FrangTestCase, H2Config
from test_suite.marks import parameterize_class

NGINX_CONFIG = {
    "id": "nginx",
    "type": "nginx",
    "status_uri": "http://${server_ip}:8000/nginx_status",
    "config": """
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
            return 404;
        }
        location /uri2 {
            return 200;
        }
        location /uri3 {
            return 405;
        }
        location /nginx_status {
            stub_status on;
        }
    }
}
""",
}


@parameterize_class(
    [
        {"name": "Http", "clients": FrangTestCase.clients},
        {"name": "H2", "clients": H2Config.clients},
    ]
)
class HttpRespCodeBlockOneClient(FrangTestCase):
    backends = [NGINX_CONFIG]

    uri_200 = "/uri2"
    uri_404 = "/uri1"
    uri_405 = "/uri3"

    warning = "frang: http_resp_code_block limit exceeded for"

    def set_frang_config_no_shc(self, frang_config: str):
        self.set_frang_config(frang_config + "\nhttp_strict_host_checking false;")

    def test_not_reaching_the_limit(self):
        client = self.get_client("deproxy-1")

        self.set_frang_config("http_resp_code_block 404 405 6 2;")
        client.start()

        for rps, requests in [
            (2.8, [client.create_request(method="GET", uri=self.uri_404, headers=[]).msg] * 7),
            (10, [client.create_request(method="GET", uri=self.uri_200, headers=[]).msg] * 10),
        ]:
            with self.subTest():
                client.set_rps(rps)
                client.make_requests(requests)
                client.wait_for_response()

                self.assertFalse(client.connection_is_closed())
                self.assertFrangWarning(warning=self.warning, expected=0)

    def test_reaching_the_limit(self):
        """
        Client send 7 requests. It receives 3 404 responses and 4 404 responses.
        Client will be blocked.
        """
        self.set_frang_config_no_shc("http_resp_code_block 404 405 6 2;")

        client = self.get_client("deproxy-1")
        client.start()
        client.make_requests(
            [client.create_request(method="GET", uri=self.uri_405, headers=[]).msg] * 3
            + [client.create_request(method="GET", uri=self.uri_404, headers=[]).msg] * 4
        )
        client.wait_for_response()

        self.assertTrue(client.wait_for_connection_close())
        self.assertFrangWarning(warning=self.warning, expected=1)

    def test_reaching_the_limit_2(self):
        """
        Client send irregular chain of 404, 405 and 200 requests with 5 rps.
        8 requests: [ '200', '404', '404', '404', '404', '200', '405', '405'].
        Client will be blocked.
        """
        self.set_frang_config("http_resp_code_block 404 405 5 2;")

        client = self.get_client("deproxy-1")
        client.start()
        client.make_requests(
            [client.create_request(method="GET", uri=self.uri_200, headers=[]).msg]
            + [client.create_request(method="GET", uri=self.uri_404, headers=[]).msg] * 4
            + [client.create_request(method="GET", uri=self.uri_200, headers=[]).msg]
            + [client.create_request(method="GET", uri=self.uri_405, headers=[]).msg] * 2
        )
        client.wait_for_response()

        self.assertTrue(client.wait_for_connection_close())
        self.assertFrangWarning(warning=self.warning, expected=1)


class HttpRespCodeBlock(FrangTestCase):
    """
    Blocks an attacker's IP address if a protected web application return
    5 error responses with codes 404 or 405 within 2 seconds. This is 2,5 per second.
    """

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
            "interface": True,
            "rps": 6,
        },
        {
            "id": "deproxy2",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
            "interface": True,
            "rps": 5,
        },
        {
            "id": "deproxy3",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
            "rps": 5,
        },
        {
            "id": "deproxy4",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
            "rps": 5,
        },
    ]

    backends = [NGINX_CONFIG]

    warning = "frang: http_resp_code_block limit exceeded for"

    tempesta = {
        "config": """
server ${server_ip}:8000;

frang_limits {
    http_resp_code_block 404 405 5 2;
    ip_block on;
}

""",
    }

    requests = ["GET /uri1 HTTP/1.1\r\nHost: localhost\r\n\r\n"]
    requests2 = ["GET /uri2 HTTP/1.1\r\nHost: localhost\r\n\r\n"]

    def test_two_clients_one_ip(self):
        """
        Two clients to be blocked by ip for a total of 404 requests
        """
        self.start_all_services(client=False)

        deproxy_cl = self.get_client("deproxy3")
        deproxy_cl.start()

        deproxy_cl2 = self.get_client("deproxy4")
        deproxy_cl2.start()

        deproxy_cl.make_requests(self.requests * 10)
        self.assertIsNone(deproxy_cl.wait_for_response(timeout=4))

        deproxy_cl2.make_requests(self.requests2 * 10)
        self.assertIsNone(deproxy_cl2.wait_for_response(timeout=6))

        self.assertEqual(5, len(deproxy_cl.responses))
        self.assertEqual(0, len(deproxy_cl2.responses))

        self.assertTrue(deproxy_cl.wait_for_connection_close())
        self.assertTrue(deproxy_cl2.wait_for_connection_close())

        self.assertFrangWarning(warning=self.warning, expected=1)

    def test_two_clients_two_ip(self):
        """
        Two clients. One client sends 12 requests by 6 per second during
        2 seconds. Of these, 6 requests by 3 per second give 404 responses and
        should be blocked after 10 responses (5 with code 200 and 5 with code 404).
        The second client sends 20 requests by 5 per second during 4 seconds.
        Of these, 10 requests by 2.5 per second give 404 responses and should not be
        blocked.
        """
        self.start_all_services(client=False)

        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.start()

        deproxy_cl2 = self.get_client("deproxy2")
        deproxy_cl2.start()

        deproxy_cl.make_requests((self.requests + self.requests2) * 6)
        deproxy_cl2.make_requests((self.requests + self.requests2) * 10)

        self.assertIsNone(deproxy_cl.wait_for_response(timeout=4))
        self.assertTrue(deproxy_cl2.wait_for_response(timeout=6))

        self.assertEqual(10, len(deproxy_cl.responses))
        self.assertEqual(20, len(deproxy_cl2.responses))

        self.assertTrue(deproxy_cl.wait_for_connection_close())
        self.assertFalse(deproxy_cl2.connection_is_closed())

        self.assertFrangWarning(warning=self.warning, expected=1)


class HttpRespCodeBlockH2(HttpRespCodeBlock):
    tempesta = {
        "config": """
    listen 443 proto=h2;
    server ${server_ip}:8000;

    frang_limits {
        http_strict_host_checking false;
        http_resp_code_block 404 405 5 2;
        ip_block on;
    }
    
    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;
    tls_match_any_server_name;
    """,
    }

    requests = [
        [
            (":authority", "example.com"),
            (":path", "/uri1"),
            (":scheme", "https"),
            (":method", "GET"),
        ],
    ]
    requests2 = [
        [
            (":authority", "example.com"),
            (":path", "/uri2"),
            (":scheme", "https"),
            (":method", "GET"),
        ],
    ]

    def setUp(self):
        self.clients = [{**client, "ssl": True} for client in self.clients]
        for client in self.clients:
            client["type"] = "deproxy_h2"
            client["port"] = "443"
        super().setUp()
