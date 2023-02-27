"""Functional tests for adding user difined headers."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester


class TestReqAddHeader(tester.TempestaTest):
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
    headers = [("x-my-hdr", "some text"), ("x-my-hdr-2", "some other text")]
    cache = False
    directive = "req_hdr_add"
    steps = 1

    def update_tempesta_config(self, config: str):
        tempesta = self.get_tempesta()

        cache = "cache 2;\ncache_fulfill * *;\n" if self.cache else "cache 0;"

        tempesta.config.defconfig += config + "\n" + cache

    def base_scenario(self, config: str, headers: list):
        client = self.get_client("deproxy-1")
        server = self.get_server("deproxy")

        self.update_tempesta_config(config=config)

        self.start_all_services()

        for _ in range(self.steps):
            client.send_request(self.request, "200")

            for header in headers:
                if self.directive in ["req_hdr_set", "req_hdr_add"]:
                    self.assertIn(header, server.last_request.headers.items())
                    self.assertNotIn(header, client.last_response.headers.items())
                else:
                    self.assertIn(header, client.last_response.headers.items())
                    self.assertNotIn(header, server.last_request.headers.items())

        return client, server

    def test_add_one_hdr(self):
        client, server = self.base_scenario(
            config=(f'{self.directive} {self.headers[0][0]} "{self.headers[0][1]}";\n'),
            headers=[self.headers[0]],
        )
        return client, server

    def test_add_some_hdrs(self):
        client, server = self.base_scenario(
            config=(
                f'{self.directive} {self.headers[0][0]} "{self.headers[0][1]}";\n'
                f'{self.directive} {self.headers[1][0]} "{self.headers[1][1]}";\n'
            ),
            headers=self.headers,
        )
        return client, server

    def test_add_some_hdrs_custom_location(self):
        client, server = self.base_scenario(
            config=(
                'location prefix "/" {\n'
                f'{self.directive} {self.headers[0][0]} "{self.headers[0][1]}";\n'
                f'{self.directive} {self.headers[1][0]} "{self.headers[1][1]}";\n'
                "}\n"
            ),
            headers=self.headers,
        )
        return client, server

    def test_add_hdrs_derive_config(self):
        client, server = self.base_scenario(
            config=(
                f'{self.directive} {self.headers[0][0]} "{self.headers[0][1]}";\n'
                'location prefix "/" {}\n'
            ),
            headers=[self.headers[0]],
        )
        return client, server

    def test_add_hdrs_override_config(self):
        client, server = self.base_scenario(
            config=(
                f'{self.directive} {self.headers[0][0]} "{self.headers[0][1]}";\n'
                'location prefix "/" {\n'
                f'{self.directive} {self.headers[1][0]} "{self.headers[1][1]}";\n'
                "}\n"
            ),
            headers=[self.headers[1]],
        )

        if self.directive == "req_hdr_add":
            self.assertNotIn(self.headers[0], server.last_request.headers.items())
        else:
            self.assertNotIn(self.headers[0], client.last_response.headers.items())

        return client, server


class TestRespAddHeader(TestReqAddHeader):

    directive = "resp_hdr_add"


class TestCachedRespAddHeader(TestReqAddHeader):
    cache = True
    directive = "resp_hdr_add"
    steps = 2


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
            self.assertIn(
                ("x-my-hdr-2", "other original text"), server.last_request.headers.items()
            )
        else:
            self.assertNotIn(("x-my-hdr", "original text"), client.last_response.headers.items())
            self.assertIn(
                ("x-my-hdr-2", "other original text"), client.last_response.headers.items()
            )

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


class TestRespSetHeader(TestReqSetHeader):

    directive = "resp_hdr_set"


class TestCachedRespSetHeader(TestRespSetHeader):
    cache = True
    steps = 2


class TestReqDelHeader(TestReqAddHeader):

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

    def test_add_one_hdr(self):
        client, server = self.base_scenario(
            config=(f"{self.directive} {self.headers[0][0]};\n"),
            headers=[("x-my-hdr-2", "other original text")],
        )

        if self.directive == "req_hdr_set":
            self.assertNotIn(self.headers[0][0], server.last_request.headers.keys())
        else:
            self.assertNotIn(self.headers[0][0], client.last_response.headers.keys())

        return client, server

    def test_add_some_hdrs(self):
        client, server = self.base_scenario(
            config=(
                f"{self.directive} {self.headers[0][0]};\n"
                f"{self.directive} {self.headers[1][0]};\n"
            ),
            headers=[],
        )

        if self.directive == "req_hdr_set":
            self.assertNotIn(self.headers[0][0], server.last_request.headers.keys())
            self.assertNotIn(self.headers[1][0], server.last_request.headers.keys())
        else:
            self.assertNotIn(self.headers[0][0], client.last_response.headers.keys())
            self.assertNotIn(self.headers[1][0], client.last_response.headers.keys())

        return client, server

    def test_add_some_hdrs_custom_location(self):
        client, server = self.base_scenario(
            config=(
                'location prefix "/" {\n'
                f"{self.directive} {self.headers[0][0]};\n"
                f"{self.directive} {self.headers[1][0]};\n"
                "}\n"
            ),
            headers=[],
        )

        if self.directive == "req_hdr_set":
            self.assertNotIn(self.headers[0][0], server.last_request.headers.keys())
            self.assertNotIn(self.headers[1][0], server.last_request.headers.keys())
        else:
            self.assertNotIn(self.headers[0][0], client.last_response.headers.keys())
            self.assertNotIn(self.headers[1][0], client.last_response.headers.keys())

        return client, server

    def test_add_hdrs_derive_config(self):
        client, server = self.base_scenario(
            config=(f"{self.directive} {self.headers[0][0]};\n" 'location prefix "/" {}\n'),
            headers=[("x-my-hdr-2", "other original text")],
        )

        if self.directive == "req_hdr_set":
            self.assertNotIn(self.headers[0][0], server.last_request.headers.keys())
        else:
            self.assertNotIn(self.headers[0][0], client.last_response.headers.keys())

        return client, server

    def test_add_hdrs_override_config(self):
        client, server = self.base_scenario(
            config=(
                f"{self.directive} {self.headers[0][0]};\n"
                'location prefix "/" {\n'
                f"{self.directive} {self.headers[1][0]};\n"
                "}\n"
            ),
            headers=[("x-my-hdr", "original text")],
        )

        if self.directive == "req_hdr_set":
            self.assertNotIn(self.headers[1][0], server.last_request.headers.keys())
        else:
            self.assertNotIn(self.headers[1][0], client.last_response.headers.keys())

        return client, server


class TestRespDelHeader(TestReqDelHeader):

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

    request = (
        f"GET / HTTP/1.1\r\n"
        + "Host: localhost\r\n"
        + "Connection: keep-alive\r\n"
        + "Accept: */*\r\n"
        + "\r\n"
    )

    directive = "resp_hdr_set"


class TestCachedRespDelHeader(TestRespDelHeader):
    cache = True
    steps = 2


# TODO: add tests for different vhosts, when vhosts will be implemented.
