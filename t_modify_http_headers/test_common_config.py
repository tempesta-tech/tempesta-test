"""Functional tests for adding user difined headers."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from t_modify_http_headers.utils import AddHeaderBase


class TestReqAddHeader(AddHeaderBase):
    cache = False
    directive = "req_hdr_add"
    request = (
        f"GET / HTTP/1.1\r\n"
        + "Host: localhost\r\n"
        + "Connection: keep-alive\r\n"
        + "Accept: */*\r\n"
        + "\r\n"
    )

    def test_add_one_hdr(self):
        client, server = self.base_scenario(
            config=f'{self.directive} x-my-hdr "some text";\n',
            expected_headers=[("x-my-hdr", "some text")],
        )
        return client, server

    def test_add_some_hdrs(self):
        client, server = self.base_scenario(
            config=(
                f'{self.directive} x-my-hdr "some text";\n'
                f'{self.directive} x-my-hdr-2 "some other text";\n'
            ),
            expected_headers=[("x-my-hdr", "some text"), ("x-my-hdr-2", "some other text")],
        )
        return client, server

    def test_add_some_hdrs_custom_location(self):
        client, server = self.base_scenario(
            config=(
                'location prefix "/" {\n'
                f'{self.directive} x-my-hdr "some text";\n'
                f'{self.directive} x-my-hdr-2 "some other text";\n'
                "}\n"
            ),
            expected_headers=[("x-my-hdr", "some text"), ("x-my-hdr-2", "some other text")],
        )
        return client, server

    def test_add_hdrs_derive_config(self):
        client, server = self.base_scenario(
            config=(f'{self.directive} x-my-hdr "some text";\n' 'location prefix "/" {}\n'),
            expected_headers=[("x-my-hdr", "some text")],
        )
        return client, server

    def test_add_hdrs_override_config(self):
        client, server = self.base_scenario(
            config=(
                f'{self.directive} x-my-hdr "some text";\n'
                'location prefix "/" {\n'
                f'{self.directive} x-my-hdr-2 "some other text";\n'
                "}\n"
            ),
            expected_headers=[("x-my-hdr-2", "some other text")],
        )

        if self.directive == "req_hdr_add":
            self.assertNotIn(("x-my-hdr", "some text"), server.last_request.headers.items())
        else:
            self.assertNotIn(("x-my-hdr", "some text"), client.last_response.headers.items())
        return client, server


class TestRespAddHeader(TestReqAddHeader):
    directive = "resp_hdr_add"


class TestCachedRespAddHeader(TestReqAddHeader):
    cache = True


class TestReqSetHeader(TestReqAddHeader):
    directive = "req_hdr_set"
    request = (
        f"GET / HTTP/1.1\r\n"
        + "Host: localhost\r\n"
        + "Connection: keep-alive\r\n"
        + "Accept: */*\r\n"
        + "x-my-hdr: original text\r\n"
        + "x-my-hdr-2: other original text\r\n"
        + "\r\n"
    )
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
                + "x-my-hdr-2: other original text\r\n"
                + "Content-Length: 0\r\n\r\n"
            ),
        }
    ]

    def test_add_one_hdr(self):
        client, server = super(TestReqSetHeader, self).test_add_one_hdr()

        if self.directive == "req_hdr_set":
            self.assertNotIn(("x-my-hdr", "original text"), server.last_request.headers.items())
        else:
            self.assertNotIn(("x-my-hdr", "original text"), client.last_response.headers.items())

    def test_add_some_hdrs(self):
        client, server = super(TestReqSetHeader, self).test_add_some_hdrs()

        if self.directive == "req_hdr_set":
            self.assertNotIn(("x-my-hdr", "original text"), server.last_request.headers.items())
            self.assertNotIn(
                ("x-my-hdr-2", "other original text"), server.last_request.headers.items()
            )
        else:
            self.assertNotIn(("x-my-hdr", "original text"), client.last_response.headers.items())
            self.assertNotIn(
                ("x-my-hdr-2", "other original text"), client.last_response.headers.items()
            )

    def test_add_some_hdrs_custom_location(self):
        client, server = super(TestReqSetHeader, self).test_add_some_hdrs_custom_location()

        if self.directive == "req_hdr_set":
            self.assertNotIn(("x-my-hdr", "original text"), server.last_request.headers.items())
            self.assertNotIn(
                ("x-my-hdr-2", "other original text"), server.last_request.headers.items()
            )
        else:
            self.assertNotIn(("x-my-hdr", "original text"), client.last_response.headers.items())
            self.assertNotIn(
                ("x-my-hdr-2", "other original text"), client.last_response.headers.items()
            )

    def test_add_hdrs_derive_config(self):
        client, server = super(TestReqSetHeader, self).test_add_hdrs_derive_config()

        if self.directive == "req_hdr_set":
            self.assertNotIn(("x-my-hdr", "original text"), server.last_request.headers.items())
            self.assertIn(
                ("x-my-hdr-2", "other original text"), server.last_request.headers.items()
            )
        else:
            self.assertNotIn(("x-my-hdr", "original text"), client.last_response.headers.items())
            self.assertIn(
                ("x-my-hdr-2", "other original text"), client.last_response.headers.items()
            )

    def test_add_hdrs_override_config(self):
        client, server = super(TestReqSetHeader, self).test_add_hdrs_override_config()

        if self.directive == "req_hdr_set":
            self.assertIn(("x-my-hdr", "original text"), server.last_request.headers.items())
            self.assertNotIn(
                ("x-my-hdr-2", "other original text"), server.last_request.headers.items()
            )
        else:
            self.assertIn(("x-my-hdr", "original text"), client.last_response.headers.items())
            self.assertNotIn(
                ("x-my-hdr-2", "other original text"), client.last_response.headers.items()
            )


class TestRespSetHeader(TestReqSetHeader):
    directive = "resp_hdr_set"


class TestCachedRespSetHeader(TestRespSetHeader):
    cache = True


# TODO: add tests for different vhosts, when vhosts will be implemented.
