"""Functional tests of header modification logic."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester
from helpers.deproxy import H2Response, HttpMessage, Request, Response


def generate_http1_request(optional_headers=[]) -> str:
    return (
        f"GET / HTTP/1.1\r\n"
        + "Host: localhost\r\n"
        + "Connection: keep-alive\r\n"
        + "".join(f"{header[0]}: {header[1]}\r\n" for header in optional_headers)
        + "\r\n"
    )


def generate_response(optional_headers=[]) -> str:
    return (
        "HTTP/1.1 200 OK\r\n"
        + f"Date: {HttpMessage.date_time_string()}\r\n"
        + "Server: Tempesta FW/pre-0.7.0\r\n"
        + "".join(f"{header[0]}: {header[1]}\r\n" for header in optional_headers)
        + "Content-Length: 0\r\n\r\n"
    )


def generate_h2_request(optional_headers=[]) -> list:
    return [
        (":authority", "localhost"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
    ] + optional_headers


class TestLogicBase(tester.TempestaTest, base=True):
    tempesta = {
        "config": """
    listen 80;
    listen 443 proto=h2;
    
    server ${server_ip}:8000;

    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;
    tls_match_any_server_name;
    """,
    }

    clients = [
        {
            "id": "deproxy-1",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "",
        }
    ]

    cache: bool
    requests_n: int
    directive: str
    h2: bool

    def update_tempesta_config(self, config: str):
        tempesta = self.get_tempesta()
        cache = "cache 2;\ncache_fulfill * *;\n" if self.cache else "cache 0;"
        tempesta.config.defconfig += config + "\n" + cache

    def base_scenario(self, config: str, optional_headers: list, expected_headers: list):
        self.update_tempesta_config(config=config)
        self.start_all_services()

        server = self.get_server("deproxy")
        client = self.get_client("deproxy-1")

        server.set_response(generate_response(optional_headers))

        # send 2 requests for checking cache and dynamic table
        for _ in range(2 if self.cache else self.requests_n):
            client.send_request(
                generate_h2_request(optional_headers)
                if self.h2
                else generate_http1_request(optional_headers),
                "200",
            )

        expected_response = self.check_response(optional_headers, expected_headers, client)
        expected_request = self.get_expected_request(optional_headers, expected_headers, client)

        self.assertEqual(expected_response, client.last_response)
        self.assertEqual(expected_request, server.last_request)

        return client, server

    def check_response(
        self, optional_headers: list, expected_headers: list, client
    ) -> Response or H2Response:
        if client.proto == "h2":
            tempesta_headers = [
                ("via", "2.0 tempesta_fw (Tempesta FW pre-0.7.0)"),
            ]
        else:
            tempesta_headers = [
                ("via", "1.1 tempesta_fw (Tempesta FW pre-0.7.0)"),
                ("Connection", "keep-alive"),
            ]

        if self.cache:
            tempesta_headers.append(("age", client.last_response.headers["age"]))

        if self.directive == "req":
            expected_response = generate_response(
                optional_headers=tempesta_headers + optional_headers
            )
        else:
            expected_response = generate_response(
                optional_headers=tempesta_headers + expected_headers
            )

        if client.proto == "h2":
            expected_response = H2Response(
                expected_response.replace("HTTP/1.1 200 OK", ":status: 200")
            )
        else:
            expected_response = Response(expected_response)
        expected_response.set_expected()
        return expected_response

    def get_expected_request(
        self, optional_headers: list, expected_headers: list, client
    ) -> Request:
        tempesta_headers = [
            ("X-Forwarded-For", "127.0.0.1"),
            ("via", "1.1 tempesta_fw (Tempesta FW pre-0.7.0)"),
        ]
        if self.directive == "req":
            expected_request = generate_http1_request(
                optional_headers=tempesta_headers + expected_headers
            )
        else:
            expected_request = generate_http1_request(
                optional_headers=tempesta_headers + optional_headers
            )

        if client.proto == "h2":
            expected_request = expected_request.replace("Connection: keep-alive\r\n", "")

        expected_request = Request(expected_request)
        expected_request.set_expected()

        return expected_request

    def test_set_non_exist_header(self):
        """
        Header will be added in request/response if it is missing from base request/response.
        """
        self.base_scenario(
            config=f'{self.directive}_hdr_set non-exist-header "qwe";\n',
            optional_headers=[],
            expected_headers=[("non-exist-header", "qwe")],
        )

    def test_add_non_exist_header(self):
        """
        Header will be added in request/response if it is missing from base request/response.
        """
        self.base_scenario(
            config=f'{self.directive}_hdr_add non-exist-header "qwe";\n',
            optional_headers=[],
            expected_headers=[("non-exist-header", "qwe")],
        )

    def test_delete_headers(self):
        """
        Headers must be removed from base request/response if header is in base request/response.
        """
        client, server = self.base_scenario(
            config=f"{self.directive}_hdr_set x-my-hdr;\n",
            optional_headers=[("x-my-hdr", "original header")],
            expected_headers=[],
        )

        if self.directive == "req":
            self.assertNotIn("x-my-hdr", server.last_request.headers.keys())
            self.assertIn("x-my-hdr", client.last_response.headers.keys())
        else:
            self.assertNotIn("x-my-hdr", client.last_response.headers.keys())
            self.assertIn("x-my-hdr", server.last_request.headers.keys())

    def test_delete_many_headers(self):
        """
        Headers must be removed from base request/response if header is in base request/response.
        """
        client, server = self.base_scenario(
            config=f"{self.directive}_hdr_set x-my-hdr;\n",
            optional_headers=[("x-my-hdr", "original header"), ("x-my-hdr", "original header")],
            expected_headers=[],
        )

        if self.directive == "req":
            self.assertNotIn("x-my-hdr", server.last_request.headers.keys())
            self.assertIn("x-my-hdr", client.last_response.headers.keys())
        else:
            self.assertNotIn("x-my-hdr", client.last_response.headers.keys())
            self.assertIn("x-my-hdr", server.last_request.headers.keys())

    def test_delete_special_headers(self):
        """
        Headers must be removed from base request/response if header is in base request/response.
        """
        header_name = "set-cookie" if self.directive == "resp" else "if-match"
        header_value = "test=cookie" if self.directive == "resp" else '"qwe"'
        client, server = self.base_scenario(
            config=f"{self.directive}_hdr_set {header_name};\n",
            optional_headers=[(header_name, header_value)],
            expected_headers=[],
        )

        if self.directive == "req":
            self.assertNotIn(header_name, server.last_request.headers.keys())
            self.assertIn(header_name, client.last_response.headers.keys())
        else:
            self.assertNotIn(header_name, client.last_response.headers.keys())
            self.assertIn(header_name, server.last_request.headers.keys())

    def test_delete_many_special_headers(self):
        """
        Headers must be removed from base request/response if header is in base request/response.
        """
        header_name = "set-cookie" if self.directive == "resp" else "if-match"
        header_value = "test=cookie" if self.directive == "resp" else '"qwe"'
        client, server = self.base_scenario(
            config=f"{self.directive}_hdr_set {header_name};\n",
            optional_headers=[(header_name, header_value), (header_name, header_value)],
            expected_headers=[],
        )

        if self.directive == "req":
            self.assertNotIn(header_name, server.last_request.headers.keys())
            self.assertIn(header_name, client.last_response.headers.keys())
        else:
            self.assertNotIn(header_name, client.last_response.headers.keys())
            self.assertIn(header_name, server.last_request.headers.keys())

    def test_delete_non_exist_header(self):
        """Request/response does not modify if header is missing from base request/response."""
        self.base_scenario(
            config=f"{self.directive}_hdr_set non-exist-header;\n",
            optional_headers=[],
            expected_headers=[],
        )

    def test_set_large_header(self):
        self.base_scenario(
            config=f'{self.directive}_hdr_set x-my-hdr "{"12" * 2000}";\n',
            optional_headers=[],
            expected_headers=[("x-my-hdr", "12" * 2000)],
        )


class H2Config:
    clients = [
        {
            "id": "deproxy-1",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]


class TestReqHeader(TestLogicBase):
    directive = "req"
    cache = False
    requests_n = 1
    h2 = False


class TestRespHeader(TestLogicBase):
    directive = "resp"
    cache = False
    requests_n = 1
    h2 = False


class TestCachedRespHeader(TestLogicBase):
    directive = "resp"
    cache = True
    requests_n = 2
    h2 = False


class TestReqHeaderH2(H2Config, TestLogicBase):
    directive = "req"
    cache = False
    requests_n = 2
    h2 = True


class TestRespHeaderH2(H2Config, TestLogicBase):
    directive = "resp"
    cache = False
    requests_n = 1
    h2 = True

    def test_add_header_from_static_table(self):
        """Tempesta must add header from static table as byte."""
        client, server = self.base_scenario(
            config=f'{self.directive}_hdr_set cache-control "no-cache";\n',
            optional_headers=[],
            expected_headers=[("cache-control", "no-cache")],
        )

        self.assertIn(b"\x08no-cache", client.response_buffer)

    def test_add_header_from_dynamic_table(self):
        """Tempesta must add header from dynamic table for second response."""
        self.update_tempesta_config(config=f'{self.directive}_hdr_set x-my-hdr "text";\n')
        self.start_all_services()

        optional_headers = [("x-my-hdr", "text")]
        request = generate_h2_request(optional_headers)

        client = self.get_client("deproxy-1")
        server = self.get_server("deproxy")
        server.set_response(generate_response(optional_headers))

        client.send_request(request, "200")
        self.assertIn(b"\x08x-my-hdr\x04text", client.response_buffer)

        client.send_request(request, "200")
        self.assertNotIn(b"\nx-my-hdr\x04text", client.response_buffer)
        self.assertIn(b"\xbe", client.response_buffer)


class TestCachedRespHeaderH2(H2Config, TestLogicBase):
    directive = "resp"
    cache = True
    requests_n = 2
    h2 = True
