"""Functional tests of header modification logic."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from t_modify_http_headers.utils import AddHeaderBase, H2Config


class TestReqHeader(AddHeaderBase):
    directive = "req"
    cache = False
    request = (
        f"GET / HTTP/1.1\r\n"
        + "host: localhost\r\n"
        + "Connection: keep-alive\r\n"
        + "Accept: */*\r\n"
        + "Content-Encoding: gzip\r\n"
        + "x-my-hdr: original text\r\n"
        + "x-my-hdr: original text\r\n"
        + "\r\n"
    )

    def test_set_non_exist_header(self):
        """
        Header will be added in request/response if it is missing from base request/response.
        """
        self.directive = f"{self.directive}_hdr_set"
        self.base_scenario(
            config=f'{self.directive} non-exist-header "qwe";\n',
            expected_headers=[("non-exist-header", "qwe")],
        )

    def test_delete_headers(self):
        """
        Headers must be removed from base request/response if header is in base request/response.
        """
        self.directive = f"{self.directive}_hdr_set"
        client, server = self.base_scenario(
            config=f"{self.directive} x-my-hdr;\n",
            expected_headers=[],
        )

        if self.directive == "req_hdr_set":
            self.assertNotIn("x-my-hdr", server.last_request.headers.keys())
        else:
            self.assertNotIn("x-my-hdr", client.last_response.headers.keys())

    def test_delete_non_exist_header(self):
        """Request/response does not modify if header is missing from base request/response."""
        self.directive = f"{self.directive}_hdr_set"
        self.base_scenario(
            config=f"{self.directive} non-exist-header;\n",
            expected_headers=[("x-my-hdr", "original text")],
        )

    def test_overwrite_raw_header(self):
        """New value for header must be added to old value as list."""
        self.directive = f"{self.directive}_hdr_add"
        client, server = self.base_scenario(
            config=f'{self.directive} x-my-hdr "some text";\n',
            expected_headers=[("x-my-hdr", "original text, some text")],
        )

        if self.directive == "req_hdr_add":
            self.assertNotIn(
                "original text", list(server.last_request.headers.find_all("x-my-hdr"))
            )
        else:
            self.assertNotIn(
                "original text",
                list(client.last_response.headers.find_all("x-my-hdr")),
            )

    def test_overwrite_singular_header(self):
        """New value for header must not be added."""
        self.directive = f"{self.directive}_hdr_add"
        client, server = self.base_scenario(
            config=f'{self.directive} host "tempesta";\n',
            expected_headers=[("host", "localhost")],
        )

        self.assertNotIn("tempesta", list(server.last_request.headers.find_all("host")))

    def test_overwrite_non_singular_header(self):
        """New value for header must be added to old value as list."""
        self.directive = f"{self.directive}_hdr_add"
        client, server = self.base_scenario(
            config=f'{self.directive} Content-Encoding "br";\n',
            expected_headers=[("content-encoding", "gzip, br")],
        )
        if self.directive == "req_hdr_add":
            self.assertNotIn("gzip", list(server.last_request.headers.find_all("content-encoding")))
        else:
            self.assertNotIn("gzip", list(client.last_response.headers.items("content-encoding")))

    def test_add_exist_header(self):
        """Header will be modified if 'header-value' is in base request/response."""
        self.directive = f"{self.directive}_hdr_add"
        self.base_scenario(
            config=f'{self.directive} x-my-hdr "original text";\n',
            expected_headers=[("x-my-hdr", "original text, original text")],
        )

    def test_add_large_header(self):
        self.directive = f"{self.directive}_hdr_set"
        self.base_scenario(
            config=f'{self.directive} x-my-hdr "{"12345" * 2000}";\n',
            expected_headers=[("x-my-hdr", "12345" * 2000)],
        )

    def test_multiple_appending_same_header(self):
        """All headers must be added in request/response as list."""
        self.directive = f"{self.directive}_hdr_add"
        self.base_scenario(
            config=(
                f'{self.directive} x-my-hdr-2 "first text";\n'
                f'{self.directive} x-my-hdr-2 "second text";\n'
                f'{self.directive} x-my-hdr-2 "third text";\n'
            ),
            expected_headers=[("x-my-hdr-2", "first text, second text, third text")],
        )

    def test_multiple_replacing_same_header(self):
        """Only last header must be added in request/response."""
        self.directive = f"{self.directive}_hdr_set"
        client, server = self.base_scenario(
            config=(
                f'{self.directive} x-my-hdr-2 "first text";\n'
                f'{self.directive} x-my-hdr-2 "second text";\n'
                f'{self.directive} x-my-hdr-2 "third text";\n'
            ),
            expected_headers=[("x-my-hdr-2", "third text")],
        )

        if self.directive == "req_hdr_set":
            self.assertEqual(1, len(list(server.last_request.headers.find_all("x-my-hdr-2"))))
        else:
            self.assertEqual(1, len(list(client.last_response.headers.find_all("x-my-hdr-2"))))


class TestRespHeader(TestReqHeader):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + "Date: test\r\n"
                + "Server: debian\r\n"
                + "x-my-hdr: original text\r\n"
                + "x-my-hdr: original text\r\n"
                + 'Etag: "qwe"\r\n'
                + "Content-Encoding: gzip\r\n"
                + "Content-Length: 0\r\n\r\n"
            ),
        }
    ]
    request = (
        f"GET / HTTP/1.1\r\n"
        + "Host: localhost\r\n"
        + "Connection: keep-alive\r\n"
        + "Accept: */*\r\n"
        + "\r\n"
    )
    directive = "resp"

    def test_overwrite_singular_header(self):
        """New value for header must not be added."""
        self.directive = f"{self.directive}_hdr_add"
        client, server = self.base_scenario(
            config=f'{self.directive} Etag "asd";\n',
            expected_headers=[("Etag", '"qwe"')],
        )

        self.assertNotIn('"asd"', list(client.last_response.headers.find_all("Etag")))
        self.assertNotIn('"qwe", "asd"', list(client.last_response.headers.find_all("Etag")))


class TestCachedRespHeader(TestRespHeader):
    cache = True


class TestReqHeaderH2(H2Config, TestReqHeader):
    request = [
        (":authority", "localhost"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
        ("x-my-hdr", "original text"),
        ("x-my-hdr", "original text"),
        ("content-encoding", "gzip"),
    ]


class TestRespHeaderH2(H2Config, TestRespHeader):
    def test_add_header_from_static_table(self):
        """Tempesta must add header from static table as byte."""
        self.directive = f"{self.directive}_hdr_add"
        client, server = self.base_scenario(
            config=f'{self.directive} cache-control "no-cache";\n',
            expected_headers=[("cache-control", "no-cache")],
        )

        self.assertIn(b"X/08no-cache", client.response_buffer)

    def test_add_header_from_dynamic_table(self):
        """Tempesta must add header from dynamic table for second response."""
        self.directive = f"{self.directive}_hdr_add"
        self.update_tempesta_config(config=f'{self.directive} x-my-hdr-3 "text";\n')
        self.start_all_services()

        client = self.get_client("deproxy-1")

        client.send_request(self.request, "200")
        self.assertIn(b"@\nx-my-hdr-3\x04text", client.response_buffer)

        client.send_request(self.request, "200")
        self.assertNotIn(b"@\nx-my-hdr-3\x04text", client.response_buffer)
        self.assertIn(b"\xbe", client.response_buffer)


class TestCachedRespHeaderH2(H2Config, TestCachedRespHeader):
    pass
