"""Functional tests for adding user difined headers."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester


class AddHeaderBase(tester.TempestaTest):
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
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + "Date: test\r\n"
                + "Server: debian\r\n"
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
    cache: bool
    directive: str

    def update_tempesta_config(self, config: str):
        tempesta = self.get_tempesta()
        cache = "cache 2;\ncache_fulfill * *;\n" if self.cache else "cache 0;"
        tempesta.config.defconfig += config + "\n" + cache

    def base_scenario(self, config: str, expected_headers: list):
        client = self.get_client("deproxy-1")
        server = self.get_server("deproxy")

        self.update_tempesta_config(config=config)
        self.disable_deproxy_auto_parser()
        self.start_all_services()

        for _ in range(2 if self.cache else 1):
            client.send_request(self.request, "200")

            for header in expected_headers:
                if self.directive in ["req_hdr_set", "req_hdr_add"]:
                    self.assertIn(header[1], list(server.last_request.headers.find_all(header[0])))
                    self.assertNotIn(
                        header[1], list(client.last_response.headers.find_all(header[0]))
                    )
                else:
                    self.assertIn(header[1], list(client.last_response.headers.find_all(header[0])))
                    self.assertNotIn(
                        header[1], list(server.last_request.headers.find_all(header[0]))
                    )

        return client, server


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
    cache = False
    directive = "resp_hdr_add"


class TestCachedRespAddHeader(TestReqAddHeader):
    cache = True
    directive = "resp_hdr_add"


class TestReqSetHeader(TestReqAddHeader):
    directive = "req_hdr_set"
    cache = False
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

    def header_not_in(self, header):
        server = self.get_server("deproxy")
        self.assertNotIn(header, server.last_request.headers.items())

    def header_in(self, header):
        server = self.get_server("deproxy")
        self.assertIn(header, server.last_request.headers.items())

    def test_add_some_hdrs(self):
        super(TestReqSetHeader, self).test_add_some_hdrs()
        self.header_not_in(("x-my-hdr", "original text"))
        self.header_not_in(("x-my-hdr-2", "other original text"))

    def test_add_some_hdrs_custom_location(self):
        super(TestReqSetHeader, self).test_add_some_hdrs_custom_location()
        self.header_not_in(("x-my-hdr", "original text"))
        self.header_not_in(("x-my-hdr-2", "other original text"))

    def test_add_hdrs_derive_config(self):
        super(TestReqSetHeader, self).test_add_hdrs_derive_config()
        self.header_not_in(("x-my-hdr", "original text"))
        self.header_in(("x-my-hdr-2", "other original text"))

    def test_add_hdrs_override_config(self):
        super(TestReqSetHeader, self).test_add_hdrs_override_config()
        self.header_in(("x-my-hdr", "original text"))
        self.header_not_in(("x-my-hdr-2", "other original text"))


class TestRespSetHeader(TestReqSetHeader):
    directive = "resp_hdr_set"
    cache = False

    def header_in(self, header):
        client = self.get_client("deproxy-1")
        self.assertIn(header, client.last_response.headers.items())

    def header_not_in(self, header):
        client = self.get_client("deproxy-1")
        self.assertNotIn(header, client.last_response.headers.items())


class TestCachedRespSetHeader(TestRespSetHeader):
    cache = True
    directive = "resp_hdr_set"
