"""
Tests for correct parsing of some parts of http2 messages, such as headers.
For now tests run curl as external program capable to generate h2 messages and
analises its return code.
"""

from framework import deproxy_client, tester
from http2_general.helpers import H2Base

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
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


class HeadersParsing(H2Base):
    def test_small_header_in_request(self):
        """Request with small header name length completes successfully."""
        self.start_all_services()

        client = self.get_client("deproxy")
        client.parsing = False
        for length in range(1, 5):
            header = "x" * length
            client.send_request(
                self.get_request + [(header, "test")],
                "200",
            )

    def test_capitalized_header_in_request(self):
        """The request must be treated as malformed. RFC 7540 8.1.2"""
        self.start_all_services()

        client = self.get_client("deproxy")
        client.parsing = False
        client.send_request(
            (
                self.post_request + [("Content-Length", "3")],
                "123",
            ),
            "400",
        )

    def test_transfer_encoding_header_in_request(self):
        """
        The only exception to this is the TE header field, which MAY be present in an HTTP/2
        request; when it is, it MUST NOT contain any value other than "trailers".
        RFC 9113 8.2.2
        """
        self.start_all_services()

        client = self.get_client("deproxy")
        client.parsing = False
        client.send_request(
            (
                self.post_request + [("transfer-encoding", "chunked")],
                "123",
            ),
            "400",
        )


class DuplicateSingularHeader(H2Base):
    def test_two_header_as_bytes_from_dynamic_table(self):
        client = self.get_client("deproxy")
        client.parsing = False

        self.start_all_services()

        # save "referer" header into dynamic table
        client.send_request(self.get_request + [("referer", "test1")], "200")
        # send two "referer" headers as bytes (\xbe, 62 index) from dynamic table
        client.send_request(self.get_request + [("referer", "test1"), ("referer", "test1")], "400")

    def test_header_as_string_value(self):
        client = self.get_client("deproxy")
        client.parsing = False

        self.start_all_services()

        # save "referer" header into dynamic table
        client.send_request(self.get_request + [("referer", "test1")], "200")

        client.h2_connection.send_headers(stream_id=3, headers=self.get_request, end_stream=True)
        client.methods.append("GET")
        # send two "referer" headers:
        # first as byte (\xbe, 62 index) from dynamic table
        # second as string value
        client.send_bytes(
            data=b"\x00\x00\x14\x01\x05\x00\x00\x00\x03\xbf\x84\x87\x82\xbe@\x07referer\x05test1",
            expect_response=True,
        )
        self.assertTrue(client.wait_for_response())
        self.assertEqual(client.last_response.status, "400")

    def test_header_from_static_table_and_dynamic_table(self):
        client = self.get_client("deproxy")
        client.parsing = False

        self.start_all_services()

        # save two "referer" header:
        # first as byte from static table (key) and value as string
        # second as byte from dynamic table
        client.send_request(self.get_request + [("referer", "test1"), ("referer", "test1")], "400")


class TestPseudoHeaders(H2Base):
    def test_invalid_pseudo_header(self):
        """
        Endpoints MUST NOT generate pseudo-header fields other than those defined in this document.
        RFC 9113 8.3
        """
        self.__test([(":content-length", "0")])

    def test_duplicate_pseudo_header(self):
        """
        The same pseudo-header field name MUST NOT appear more than once in a field block.
        A field block for an HTTP request or response that contains a repeated pseudo-header
        field name MUST be treated as malformed.
        RFC 9113 8.3
        """
        self.__test([(":path", "/")])

    def test_status_header_in_request(self):
        """
        Pseudo-header fields defined for responses MUST NOT appear in requests.
        RFC 9113 8.3
        """
        self.__test([(":status", "200")])

    def test_regular_header_before_pseudo_header(self):
        """
        All pseudo-header fields MUST appear in a field block before all regular field lines.
        RFC 9113 8.3
        """
        self.post_request = [
            (":authority", "example.com"),
            (":path", "/"),
            (":scheme", "https"),
        ]
        self.__test([("content-length", "0"), (":method", "POST")])

    def __test(self, optional_header: list):
        self.start_all_services()

        client = self.get_client("deproxy")
        client.parsing = False

        client.send_request(
            self.post_request + optional_header,
            "400",
        )

        self.assertTrue(client.wait_for_connection_close())


class TestConnectionHeaders(H2Base):
    def __test_request(self, header: tuple):
        """
        An endpoint MUST NOT generate an HTTP/2 message containing connection-specific
        header fields. Any message containing connection-specific header fields MUST be treated
        as malformed.
        RFC 9113 8.2.2
        """
        self.start_all_services()
        client = self.get_client("deproxy")
        client.parsing = False

        client.send_request(self.post_request + [header], "400")
        self.assertTrue(client.wait_for_connection_close())

    def __test_response(self, header: tuple):
        """
        An intermediary transforming an HTTP/1.x message to HTTP/2 MUST remove connection-specific
        header fields or their messages will be treated by other HTTP/2 endpoints as malformed.
        RFC 9113 8.2.2
        """
        self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")
        client.parsing = False

        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Date: test\r\n"
            + "Server: debian\r\n"
            + f"{header[0].capitalize()}: {header[1]}\r\n"
            + "Content-Length: 0\r\n\r\n"
        )

        client.send_request(self.post_request, "200")
        self.assertNotIn(header, client.last_response.headers.headers)

    def test_connection_header_in_request(self):
        self.__test_request(header=("connection", "keep-alive"))

    def test_keep_alive_header_in_request(self):
        self.__test_request(header=("keep-alive", "timeout=5, max=10"))

    def test_proxy_connection_header_in_request(self):
        self.__test_request(header=("proxy-connection", "keep-alive"))

    def test_upgrade_header_in_request(self):
        self.__test_request(header=("upgrade", "websocket"))

    def test_connection_header_in_response(self):
        self.__test_response(header=("connection", "keep-alive"))

    def test_keep_alive_header_in_response(self):
        self.__test_response(header=("keep-alive", "timeout=5, max=10"))

    def test_proxy_connection_header_in_response(self):
        self.__test_response(header=("proxy-connection", "keep-alive"))

    def test_upgrade_header_in_response(self):
        self.__test_response(header=("upgrade", "websocket"))


class TestIPv6(H2Base):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ipv6}",
            "port": "443",
            "ssl": True,
            "socket_family": "ipv6",
        },
    ]

    tempesta = {
        "config": """
            listen [${tempesta_ipv6}]:443 proto=h2;
            server ${server_ip}:8000;
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;

            block_action attack reply;
            block_action error reply;
        """
    }

    def test_request_with_some_data(self):
        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        self.start_all_services()

        data_size = 5000
        response_header = ("x-my-hdr", "x" * data_size)
        response_body = "x" * data_size
        request_header = ("x-my-hdr", "z" * data_size)
        request_body = "z" * data_size

        server.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Date: test\r\n"
            + "Server: debian\r\n"
            + f"{response_header[0]}: {response_header[1]}\r\n"
            + f"Content-Length: {len(response_body)}\r\n\r\n"
            + response_body
        )
        client.send_request(
            request=(self.post_request + [request_header], request_body),
            expected_status_code="200",
        )

        self.assertEqual(request_body, server.last_request.body)
        self.assertEqual(response_body, client.last_response.body)
        self.assertIn(request_header, server.last_request.headers.headers)
        self.assertIn(response_header, client.last_response.headers.headers)


class TestH2Host(H2Base):
    def test_host_missing(self):
        self.start_all_services()
        client = self.get_client("deproxy")
        client.parsing = False

        client.send_request(
            request=[
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
            ],
            expected_status_code="400",
        )

    def test_empty_authority_header(self):
        self.start_all_services()
        client = self.get_client("deproxy")
        client.parsing = False

        client.send_request(
            request=[(":path", "/"), (":scheme", "https"), (":method", "GET"), (":authority", "")],
            expected_status_code="400",
        )

    def test_empty_host_header(self):
        self.start_all_services()
        client = self.get_client("deproxy")
        client.parsing = False

        client.send_request(
            request=[(":path", "/"), (":scheme", "https"), (":method", "GET"), ("host", "")],
            expected_status_code="400",
        )

    def test_host_authority_ok(self):
        self.start_all_services()
        client = self.get_client("deproxy")
        client.parsing = False

        client.send_request(
            request=[
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
                (":authority", "localhost"),
            ],
            expected_status_code="200",
        )

    def test_host_header_ok(self):
        self.start_all_services()
        client = self.get_client("deproxy")
        client.parsing = False

        client.send_request(
            request=[
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
                ("host", "localhost"),
            ],
            expected_status_code="200",
        )

    def test_different_host_and_authority_headers(self):
        self.start_all_services()
        client = self.get_client("deproxy")
        client.parsing = False

        client.send_request(
            request=[
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
                (":authority", "deproxy"),
                ("host", "localhost"),
            ],
            expected_status_code="200",
        )

    def test_forwarded_and_empty_host_header(self):
        """Host header must be present. Forwarded header does not set host header."""
        self.start_all_services()
        client = self.get_client("deproxy")
        client.parsing = False

        client.send_request(
            request=[
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
                ("host", ""),
                ("forwarded", "host=localhost"),
            ],
            expected_status_code="400",
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


class BackendSetCoookieH2(tester.TempestaTest):
    """
    This is a H2 version of BackendSetCoookie test case
    Put special headers with same Set-Cookie name
    """

    clients = [
        {
            "id": "curl",
            "type": "external",
            "binary": "curl",
            "cmd_args": (
                "-kfv " "https://${tempesta_ip}/ "  # Set non-null return code on 4xx-5xx responses.
            ),
        },
    ]

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG
            % """
add_header Set-Cookie "wordpress_86a9106ae65537651a8e456835b316ab=admin%7C1662810634%7CY5HVGAwBX3g13hZEvGgwSf7fyUY1t5ZaPi2JsH8Fpsa%7C634effa8a901f9b410b6fd18ca0512039ffe2f362a0d70b6d82ff995b7f8be22; path=/wp-content/plugins; HttpOnly";
add_header Set-Cookie "wordpress_86a9106ae65537651a8e456835b316ab=admin%7C1662810634%7CY5HVGAwBX3g13hZEvGgwSf7fyUY1t5ZaPi2JsH8Fpsa%7C634effa8a901f9b410b6fd18ca0512039ffe2f362a0d70b6d82ff995b7f8be22; path=/wp-admin; HttpOnly";
add_header Set-Cookie "wordpress_logged_in_86a9106ae65537651a8e456835b316ab=admin%7C1662810634%7CY5HVGAwBX3g13hZEvGgwSf7fyUY1t5ZaPi2JsH8Fpsa%7Cd20c220a6974e7c1bdad6eb90b19b37986bbb06ada7bff996b55d0269c077c90; path=/; HttpOnly";

return 200;
""",
        }
    ]

    tempesta = {
        "config": TEMPESTA_CONFIG % "cache_fulfill * *;",
    }

    def test(self, served_from_cache=True):
        curl = self.get_client("curl")

        self.start_all_servers()
        self.start_tempesta()

        self.start_all_clients()
        self.wait_while_busy(curl)
        self.assertEqual(
            0, curl.returncode, msg=("Curl return code is not 0 (%d)." % (curl.returncode))
        )
        curl.stop()

        self.start_all_clients()
        self.wait_while_busy(curl)
        self.assertEqual(
            0, curl.returncode, msg=("Curl return code is not 0 (%d)." % (curl.returncode))
        )

        nginx = self.get_server("nginx")
        nginx.get_stats()
        self.assertEqual(
            1 if served_from_cache else 2,
            nginx.requests,
            msg="Unexpected number forwarded requests to backend",
        )
        setcookie_count = 0
        lines = curl.proc_results[1].decode("utf-8").split("\n")
        for line in lines:
            if line.startswith("< set-cookie:"):
                setcookie_count += 1
                self.assertTrue(len(line.split(",")) == 1, "Wrong separator")
        self.assertTrue(setcookie_count == 3, "Set-Cookie headers quantity mismatch")


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
