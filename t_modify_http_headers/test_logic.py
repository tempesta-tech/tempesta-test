"""Functional tests of header modification logic."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import helpers
from helpers import tf_cfg
from helpers.deproxy import H2Response, HttpMessage, Request, Response
from test_suite import tester

MAX_HEADER_NAME = 1024  # See fw/http_parser.c HTTP_MAX_HDR_NAME_LEN


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
        + f"Server: Tempesta FW/{helpers.tempesta.version()}\r\n"
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


def get_expected_response(
    optional_headers: list, expected_headers: list, client, cache: bool, directive: str
) -> Response or H2Response:
    if client.proto == "h2":
        tempesta_headers = [
            ("via", f"2.0 tempesta_fw (Tempesta FW {helpers.tempesta.version()})"),
        ]
    else:
        tempesta_headers = [
            ("via", f"1.1 tempesta_fw (Tempesta FW {helpers.tempesta.version()})"),
            ("Connection", "keep-alive"),
        ]

    if cache:
        tempesta_headers.append(("age", client.last_response.headers["age"]))

    if directive == "req":
        expected_response = generate_response(optional_headers=tempesta_headers + optional_headers)
    else:
        expected_response = generate_response(optional_headers=tempesta_headers + expected_headers)

    if client.proto == "h2":
        expected_response = H2Response(expected_response.replace("HTTP/1.1 200 OK", ":status: 200"))
    else:
        expected_response = Response(expected_response)
    expected_response.set_expected()
    return expected_response


def get_expected_request(
    optional_headers: list, expected_headers: list, client, directive: str
) -> Request:
    tempesta_headers = [
        ("X-Forwarded-For", tf_cfg.cfg.get("Client", "ip")),
        ("via", f"1.1 tempesta_fw (Tempesta FW {helpers.tempesta.version()})"),
    ]
    if directive == "req":
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


def update_tempesta_config(tempesta, config: str, cache: bool):
    cache = "cache 2;\ncache_fulfill * *;\n" if cache else "cache 0;"
    tempesta.config.defconfig += config + "\n" + cache


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

    def base_scenario(self, config: str, optional_headers: list, expected_headers: list):
        update_tempesta_config(tempesta=self.get_tempesta(), config=config, cache=self.cache)
        self.start_all_services()
        self.disable_deproxy_auto_parser()

        server = self.get_server("deproxy")
        client = self.get_client("deproxy-1")

        server.set_response(generate_response(optional_headers))

        # send 2 requests for checking cache and dynamic table
        for _ in range(2 if self.cache else self.requests_n):
            client.send_request(
                (
                    generate_h2_request(optional_headers)
                    if self.h2
                    else generate_http1_request(optional_headers)
                ),
                "200",
            )

        expected_response = get_expected_response(
            optional_headers, expected_headers, client, self.cache, self.directive
        )
        expected_request = get_expected_request(
            optional_headers, expected_headers, client, self.directive
        )

        client.last_response.headers.delete_all("Date")
        expected_response.headers.delete_all("Date")
        self.assertEqual(expected_response, client.last_response)
        self.assertEqual(expected_request, server.last_request)

        return client, server

    def test_set_non_exist_header(self):
        """
        Header will be added in request/response if it is missing from base request/response.
        """
        self.base_scenario(
            config=f'{self.directive}_hdr_set non-exist-header "qwe";\n',
            optional_headers=[],
            expected_headers=[("non-exist-header", "qwe")],
        )

    def test_set_exist_header(self):
        self.base_scenario(
            config=f'{self.directive}_hdr_set exist-header "qwe";\n',
            optional_headers=[("exist-header", "123")],
            expected_headers=[("exist-header", "qwe")],
        )

    def test_set_exist_special_header(self):
        header_name = "set-cookie" if self.directive == "resp" else "if-none-match"
        header_value = "test=cookie" if self.directive == "resp" else '"qwe"'
        new_hdr_value = '"test=cookie2"' if self.directive == "resp" else r'"\"asd\""'
        expected_new_hdr_value = "test=cookie2" if self.directive == "resp" else r'"asd"'
        self.base_scenario(
            config=f"{self.directive}_hdr_set {header_name} {new_hdr_value};\n",
            optional_headers=[(header_name, header_value)],
            expected_headers=[(header_name, expected_new_hdr_value)],
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
        header_name = "set-cookie" if self.directive == "resp" else "if-none-match"
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
        header_name = "set-cookie" if self.directive == "resp" else "forwarded"
        header_value = "test=cookie" if self.directive == "resp" else "for=tempesta.com"
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

    def test_set_header_name_greater_than_1024(self):
        self.base_scenario(
            config=f'{self.directive}_hdr_set {"a" * (MAX_HEADER_NAME + 10)} "value";\n',
            optional_headers=[],
            expected_headers=[("a" * (MAX_HEADER_NAME + 10), "value")],
        )

    def test_set_long_header_name(self):
        self.base_scenario(
            config=(
                f'{self.directive}_hdr_set {"a" * MAX_HEADER_NAME} "value";\n'
                f'{self.directive}_hdr_set {"b" * MAX_HEADER_NAME} "value";\n'
                f'{self.directive}_hdr_set {"c" * MAX_HEADER_NAME} "value";\n'
                f'{self.directive}_hdr_set {"d" * MAX_HEADER_NAME} "value";\n'
            ),
            optional_headers=[],
            expected_headers=[
                ("a" * MAX_HEADER_NAME, "value"),
                ("b" * MAX_HEADER_NAME, "value"),
                ("c" * MAX_HEADER_NAME, "value"),
                ("d" * MAX_HEADER_NAME, "value"),
            ],
        )

    def test_long_header_name(self):
        self.base_scenario(
            config=f'{self.directive}_hdr_set {"a" * MAX_HEADER_NAME} "value1";\n',
            optional_headers=[
                ("a" * MAX_HEADER_NAME, "value"),
                ("a" * MAX_HEADER_NAME, "value"),
                ("a" * MAX_HEADER_NAME, "value"),
                ("a" * MAX_HEADER_NAME, "value"),
            ],
            expected_headers=[
                ("a" * MAX_HEADER_NAME, "value1"),
            ],
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


class TestManyRequestHeaders(tester.TempestaTest):
    tempesta = TestLogicBase.tempesta

    clients = TestLogicBase.clients

    backends = TestLogicBase.backends

    cache = False
    directive = "req"
    h2 = False
    requests_n = 1
    __headers_n = 64 // 4

    def test_many_headers(self):
        set_headers = [(f"set-header-{step}", str(step) * 1000) for step in range(self.__headers_n)]
        add_headers = [(f"add-header-{step}", str(step) * 1000) for step in range(self.__headers_n)]
        exist_header = [
            (f"exist-header-{step}", str(step) * 500) for step in range(self.__headers_n)
        ]
        changed_headers = [
            (f"changed-header-{step}", f"{step}a") for step in range(self.__headers_n)
        ]
        expected_changed_header = [
            (header[0], header[1].replace("a", "")) for header in changed_headers
        ]

        config = [
            f'{self.directive}_hdr_set {header[0]} "{header[1]}";\n' for header in set_headers
        ]
        config.extend(
            f'{self.directive}_hdr_add {header[0]} "{header[1]}";\n' for header in add_headers
        )
        config.extend(f"{self.directive}_hdr_set {header[0]};\n" for header in exist_header)
        config.extend(
            f'{self.directive}_hdr_set {header[0]} "{header[1]}";\n'
            for header in expected_changed_header
        )

        TestLogicBase.base_scenario(
            self,
            config="".join(config),
            optional_headers=exist_header + changed_headers,
            expected_headers=set_headers + add_headers + expected_changed_header,
        )


class TestManyResponseHeaders(TestManyRequestHeaders):
    cache = False
    directive = "resp"
    h2 = False
    requests_n = 1


class TestManyCachedResponseHeaders(TestManyRequestHeaders):
    cache = True
    directive = "resp"
    h2 = False
    requests_n = 2


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

        self.assertIn(b"\x08no-cache", client.last_response_buffer)

    def test_add_header_from_dynamic_table(self):
        """Tempesta must add header from dynamic table for second response."""
        update_tempesta_config(
            tempesta=self.get_tempesta(),
            config=f'{self.directive}_hdr_set x-my-hdr "text";\n',
            cache=self.cache,
        )
        self.start_all_services()

        optional_headers = [("x-my-hdr", "text")]
        request = generate_h2_request(optional_headers)

        client = self.get_client("deproxy-1")
        server = self.get_server("deproxy")
        server.set_response(generate_response(optional_headers))

        client.send_request(request, "200")
        self.assertIn(b"\x08x-my-hdr\x04text", client.last_response_buffer)

        client.send_request(request, "200")
        self.assertNotIn(b"x-my-hdr\x04text", client.last_response_buffer)
        self.assertIn(b"\xbe", client.last_response_buffer)


class TestCachedRespHeaderH2(H2Config, TestLogicBase):
    directive = "resp"
    cache = True
    requests_n = 2
    h2 = True

    def test_add_header_from_static_table(self):
        TestRespHeaderH2.test_add_header_from_static_table(self)


class TestManyRequestHeadersH2(H2Config, TestManyRequestHeaders):
    cache = False
    directive = "req"
    h2 = True
    requests_n = 2


class TestManyResponseHeadersH2(H2Config, TestManyRequestHeaders):
    cache = False
    directive = "resp"
    h2 = True
    requests_n = 2


class TestManyCachedResponseHeadersH2(H2Config, TestManyRequestHeaders):
    cache = True
    directive = "resp"
    h2 = True
    requests_n = 2


class TestReqHdrSetHost(tester.TempestaTest):
    """
    Case for `Host` header.

    `Host` header in the request must be replaced with header - "host: host-overriden"
    """

    tempesta = TestLogicBase.tempesta

    clients = TestLogicBase.clients

    backends = TestLogicBase.backends

    directive = "req"
    h2 = False

    def get_expected_request_no_host(self, expected_headers: list) -> Request:
        tempesta_headers = [
            ("X-Forwarded-For", tf_cfg.cfg.get("Client", "ip")),
            ("via", f"1.1 tempesta_fw (Tempesta FW {helpers.tempesta.version()})"),
        ]

        request = (
            f"GET / HTTP/1.1\r\n"
            + "".join(
                f"{header[0]}: {header[1]}\r\n" for header in expected_headers + tempesta_headers
            )
            + ("Connection: keep-alive\r\n" if not self.h2 else "")
            + "\r\n"
        )

        expected_request = Request(request)
        expected_request.set_expected()

        return expected_request

    def test_req_hdr_set_host(self):
        expected_headers = [("host", "host-overriden")]
        config = f'{self.directive}_hdr_set host "host-overriden";\n'
        update_tempesta_config(tempesta=self.get_tempesta(), config=config, cache=False)
        self.start_all_services()
        self.disable_deproxy_auto_parser()

        server = self.get_server("deproxy")
        client = self.get_client("deproxy-1")

        server.set_response(generate_response())

        client.send_request(
            generate_h2_request() if self.h2 else generate_http1_request(),
            "200",
        )

        expected_response = get_expected_response(
            [], expected_headers, client, False, self.directive
        )
        expected_request = self.get_expected_request_no_host(expected_headers)

        client.last_response.headers.delete_all("Date")
        expected_response.headers.delete_all("Date")
        msg_resp = f"\nExpected:\n{expected_response}\nReceived:\n{client.last_response}"
        msg_req = f"\nExpected:\n{expected_request}\nReceived:\n{server.last_request}"
        self.assertEqual(expected_response, client.last_response, msg=msg_resp)
        self.assertEqual(expected_request, server.last_request, msg=msg_req)


class TestReqHdrSetHostH2(H2Config, TestReqHdrSetHost):
    """
    Case for `Host` header.

    `Host` header in the request must be replaced with header - "host: host-overriden"
    """

    h2 = True
