"""
Tests for correct parsing of some parts of http2 messages, such as headers.
For now tests run curl as external program capable to generate h2 messages and
analises its return code.
"""

from framework import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

NGINX_CONFIG = """
pid ${pid};
worker_processes  auto;

events {
    worker_connections   1024;
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
            %s
        }
        location /nginx_status {
            stub_status on;
        }
    }
}
"""

TEMPESTA_CONFIG = """
listen 443 proto=h2;

srv_group default {
    server ${server_ip}:8000;
}
vhost default {
    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;

    proxy_pass default;
}
%s
"""

TEMPESTA_DEPROXY_CONFIG = """
listen 443 proto=h2;

srv_group default {
    server ${general_ip}:8000;
}
vhost default {
    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;

    proxy_pass default;
}
%s
"""


class HeadersParsing(tester.TempestaTest):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        }
    ]

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        }
    ]

    tempesta = {
        "config": TEMPESTA_CONFIG % "",
    }

    def test_small_header_in_request(self):
        """Request with small header name length completes successfully."""
        self.start_all_services()

        client = self.get_client("deproxy")
        client.parsing = False
        for length in range(1, 5):
            header = "x" * length
            client.send_request(
                [
                    (":authority", "localhost"),
                    (":path", "/"),
                    (":scheme", "https"),
                    (":method", "GET"),
                    (header, "test"),
                ],
                "200",
            )

    def test_capitalized_header_in_request(self):
        """The request must be treated as malformed. RFC 7540 8.1.2"""
        self.start_all_services()

        client = self.get_client("deproxy")
        client.parsing = False
        client.send_request(
            (
                [
                    (":authority", "localhost"),
                    (":path", "/"),
                    (":scheme", "https"),
                    (":method", "POST"),
                    ("Content-Length", "3"),
                ],
                "123",
            ),
            "400",
        )

    def test_chunked_header_in_request(self):
        """The request must be treated as malformed. RFC 7540 8.2.2"""
        self.start_all_services()

        client = self.get_client("deproxy")
        client.parsing = False
        client.send_request(
            (
                [
                    (":authority", "localhost"),
                    (":path", "/"),
                    (":scheme", "https"),
                    (":method", "POST"),
                    ("transfer-encoding", "chunked"),
                ],
                "3\r\n123\r\n0\r\n\r\n",
            ),
            "400",
        )


class CurlTestBase(tester.TempestaTest):

    clients = [
        {
            "id": "curl",
            "type": "external",
            "binary": "curl",
            "cmd_args": ("-kfv " "https://${tempesta_ip}/ "),
        },
    ]

    def run_test(self, served_from_cache=False):
        curl = self.get_client("curl")

        self.start_all_servers()
        self.start_tempesta()

        self.start_all_clients()
        self.wait_while_busy(curl)
        curl.stop()
        self.assertIn("200", curl.response_msg)

        self.start_all_clients()
        self.wait_while_busy(curl)
        curl.stop()
        self.assertIn("200", curl.response_msg)

        nginx = self.get_server("nginx")
        nginx.get_stats()
        self.assertEqual(
            1 if served_from_cache else 2,
            nginx.requests,
            msg="Unexpected number forwarded requests to backend",
        )

    def run_deproxy_test(self, served_from_cache=False):
        curl = self.get_client("curl")

        self.start_all_servers()
        self.start_tempesta()

        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections())

        self.wait_while_busy(curl)
        curl.stop()
        self.assertIn("200", curl.response_msg)

        self.start_all_clients()
        self.wait_while_busy(curl)
        curl.stop()
        self.assertIn("200", curl.response_msg)

        srv = self.get_server("deproxy")
        self.assertEqual(
            1 if served_from_cache else 2,
            len(srv.requests),
            msg="Unexpected number forwarded requests to backend",
        )


class AddBackendShortHeaders(CurlTestBase):
    """The test checks the correctness of forwarding short headers with
    duplication in mixed order: put header B between two headers A
    """

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG
            % """
add_header x-extra-data1 "q";
add_header x-extra-data2 "q";
add_header x-extra-data1 "q";

return 200;
""",
        }
    ]

    tempesta = {
        "config": TEMPESTA_CONFIG % "",
    }

    def test(self):
        CurlTestBase.run_test(self)


class AddBackendShortHeadersCache(CurlTestBase):
    """The test checks the correctness of serving short headers with duplicate
    (in mixed order: put header B between two headers A) from the cache
    """

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG
            % """
add_header x-extra-data1 "q";
add_header x-extra-data2 "q";
add_header x-extra-data1 "q";

return 200;
""",
        }
    ]

    tempesta = {
        "config": TEMPESTA_CONFIG % "cache_fulfill * *;",
    }

    def test(self):
        CurlTestBase.run_test(self, served_from_cache=True)


class AddBackendLongHeaders(CurlTestBase):
    """The test checks the correctness of forwarding long headers with
    duplication in mixed order: put header B between two headers A
    """

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG
            % """
add_header x-extra-data "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data1 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data2 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data3 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data3 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data4 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data4 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data5 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data5 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data6 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data6 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data7 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data7 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data8 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data8 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data9 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data9 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data1 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data1 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";

return 200;
""",
        }
    ]

    tempesta = {
        "config": TEMPESTA_CONFIG % "",
    }

    def test(self):
        CurlTestBase.run_test(self)


class AddBackendLongHeadersCache(CurlTestBase):
    """The test checks the correctness of serving long headers with duplicate
    (in mixed order: put header B between two headers A) from the cache
    """

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG
            % """
add_header x-extra-data "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data1 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data2 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data3 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data3 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data4 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data4 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data5 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data5 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data6 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data6 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data7 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data7 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data8 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data8 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data9 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data9 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data1 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";
add_header x-extra-data1 "qwertyuiopasdfghjklzxcvbnmqqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnmwertyuiopasdfghjklzxcvbnm";

return 200;
""",
        }
    ]

    tempesta = {
        "config": TEMPESTA_CONFIG % "cache_fulfill * *;",
    }

    def test(self):
        CurlTestBase.run_test(self, served_from_cache=True)


class LowercaseAddBackendHeaders(CurlTestBase):
    """Test on converting header names to lowercase when converting a forwarded
    response to h2. If the conversion fails, curl will not return 0 and the test
    will fail.
    """

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG
            % """
add_header X-Extra-Data1 "q";
add_header X-Extra-Data2 "q";
add_header X-Extra-Data1 "q";

return 200;
""",
        }
    ]

    tempesta = {
        "config": TEMPESTA_CONFIG % "",
    }

    def test(self):
        CurlTestBase.run_test(self)


class LowercaseAddBackendHeadersCache(CurlTestBase):
    """Test on converting header names to lowercase if response is served by
    cache. If the conversion fails, curl will not return 0 and the test will
    fail.
    """

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG
            % """
add_header X-Extra-Data1 "q";
add_header X-Extra-Data2 "q";
add_header X-Extra-Data1 "q";

return 200;
""",
        }
    ]

    tempesta = {
        "config": TEMPESTA_CONFIG % "cache_fulfill * *;",
    }

    def test(self):
        CurlTestBase.run_test(self, served_from_cache=True)


def deproxy_backend_config(headers):
    return {
        "id": "deproxy",
        "type": "deproxy",
        "port": "8000",
        "response": "static",
        "response_content": headers,
    }


class HeadersEmptyCache(CurlTestBase):
    """Empty headers in responses might lead to kernel panic
    (see tempesta issue #1549).
    """

    backends = [
        deproxy_backend_config(
            "HTTP/1.1 200 OK\r\n"
            "Server-id: deproxy\r\n"
            "Content-Length: 0\r\n"
            "Pragma:\r\n"
            "Empty-header:\r\n"
            "X-Extra-Data:\r\n\r\n"
        )
    ]

    tempesta = {
        "config": TEMPESTA_DEPROXY_CONFIG % "cache_fulfill * *;",
    }

    def test(self):
        CurlTestBase.run_deproxy_test(self, served_from_cache=True)


class HeadersSpacedCache(CurlTestBase):
    """Same as EmptyHeadersCache, but with spaces as header values."""

    backends = [
        deproxy_backend_config(
            "HTTP/1.1 200 OK\r\n"
            "Server-id: deproxy\r\n"
            "Content-Length: 0\r\n"
            "Pragma: \r\n"
            "Empty-header: \r\n"
            "X-Extra-Data: \r\n\r\n"
        )
    ]

    tempesta = {
        "config": TEMPESTA_DEPROXY_CONFIG % "cache_fulfill * *;",
    }

    def test(self):
        CurlTestBase.run_deproxy_test(self, served_from_cache=True)


class MissingDateServerWithBodyTest(tester.TempestaTest):
    """
    Test response without Date and Server headers, but with short body.
    This test need to verify transforming of HTTP/1 responses to HTTP/2
    which doesn't have Date and Server headers but has a body. At forwarding
    response stage tempesta adds its Server and Date and we need to ensure
    this passed correctly. Exist tests uses nginx to respond to HTTP2,
    but nginx returns Server and Date by default. Also, in most tests body
    not present in response.
    """

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 1\r\n\r\n" "1",
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

    def test(self):
        self.start_all()

        head = [
            (":authority", "localhost"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "GET"),
        ]

        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.make_request(head)

        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(resp)
        self.assertEqual(deproxy_cl.last_response.status, "200")


LARGE_CONTENT_LENGTH = 1024 * 8


class MissingDateServerWithLargeBodyTest(MissingDateServerWithBodyTest):
    """
    Same as `MissingDateServerWithBodyTest`, but with a larger body.
    Can cause panic, see Tempesta issue #1704
    """

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                f"Content-Length: {LARGE_CONTENT_LENGTH}\r\n"
                "\r\n"
                f"{'1' * LARGE_CONTENT_LENGTH}"
            ),
        },
    ]
