"""Tests for Frang directive `http_methods`."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from t_frang.frang_test_case import FrangTestCase, H2Config


class FrangHttpMethodsTestCase(FrangTestCase):
    error = "frang: restricted HTTP method"

    def test_accepted_request(self):
        client = self.base_scenario(
            frang_config="http_methods get post;",
            requests=[
                "GET / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n",
                "POST / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n",
            ],
        )
        self.check_response(client, status_code="200", warning_msg=self.error)

    def test_not_accepted_request(self):
        client = self.base_scenario(
            frang_config="http_methods get post;",
            requests=["DELETE / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n"],
            disable_hshc=True,
        )
        self.check_response(client, status_code="403", warning_msg=self.error)

    def test_accepted_request_shipping_cfg(self):
        client = self.base_scenario(
            # Task #2058: On the shipping cfg only GET/POST/HEAD allowed.
            frang_config="",
            requests=[
                "GET / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n",
                "POST / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n",
                "HEAD / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n",
            ],
        )
        self.check_response(client, status_code="200", warning_msg=self.error)

    def test_not_accepted_request_shipping_cfg(self):
        """
        Test that HTTP methods DELETE, PUT, OPTIONS, PATCH, TRACE and CONNECT are not
        accepted on the shipping configuration.
        """
        client = self.base_scenario(
            frang_config="",
            requests=[
                "DELETE / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n",
                "PUT / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n",
                "OPTIONS / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n",
                "PATCH / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n",
                "TRACE / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n",
                "CONNECT / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n",
            ],
            disable_hshc=True,
        )
        self.check_response(client, status_code="403", warning_msg=self.error)

    def test_not_accepted_request_register(self):
        self.disable_deproxy_auto_parser()
        client = self.base_scenario(
            frang_config="http_methods get post;",
            requests=["gEt / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n"],
            disable_hshc=True,
        )
        self.check_response(client, status_code="403", warning_msg=self.error)

    def test_not_accepted_request_with_unknown_method(self):
        client = self.base_scenario(
            frang_config="http_methods get post;",
            requests=["UNKNOWN / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n"],
            disable_hshc=True,
        )
        self.check_response(client, status_code="403", warning_msg=self.error)

    def test_accepted_request_with_unknown_method(self):
        client = self.base_scenario(
            frang_config="http_methods get post unknown;",
            requests=["UNKNOWN / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n"],
            disable_hshc=True,
        )
        self.check_response(client, status_code="200", warning_msg=self.error)

    def test_not_accepted_request_owerride(self):
        client = self.base_scenario(
            frang_config="http_methods get post;",
            requests=[
                "PUT / HTTP/1.1\r\nHost: tempesta-tech.com\r\nX-HTTP-Method-Override: GET\r\n\r\n"
            ],
            disable_hshc=True,
        )
        self.check_response(client, status_code="403", warning_msg=self.error)


class FrangHttpMethodsH2(H2Config, FrangHttpMethodsTestCase):
    def test_accepted_request(self):
        put_request = [
            (":authority", "example.com"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "PUT"),
        ]
        client = self.base_scenario(
            frang_config="http_methods get post put;",
            requests=[self.get_request, self.post_request, put_request, put_request],
            disable_hshc=True,
        )
        self.check_response(client, status_code="200", warning_msg=self.error)

    def test_not_accepted_request(self):
        client = self.base_scenario(
            frang_config="http_methods get post;",
            requests=[
                [
                    (":authority", "example.com"),
                    (":path", "/"),
                    (":scheme", "https"),
                    (":method", "DELETE"),
                ],
            ],
            disable_hshc=True,
        )
        self.check_response(client, status_code="403", warning_msg=self.error)

    def test_accepted_request_shipping_cfg(self):
        # Task #2058: On the shipping cfg only GET/POST/HEAD allowed.
        client = self.base_scenario(
            frang_config="",
            requests=[
                [
                    (":authority", "example.com"),
                    (":path", "/"),
                    (":scheme", "https"),
                    (":method", "GET"),
                ],
                [
                    (":authority", "example.com"),
                    (":path", "/"),
                    (":scheme", "https"),
                    (":method", "POST"),
                ],
                [
                    (":authority", "example.com"),
                    (":path", "/"),
                    (":scheme", "https"),
                    (":method", "HEAD"),
                ],
            ],
            disable_hshc=True,
        )
        self.check_response(client, status_code="200", warning_msg=self.error)

    def test_not_accepted_request_shipping_cfg(self):
        """
        Test that HTTP methods DELETE, PUT, OPTIONS, PATCH, TRACE and CONNECT are not
        accepted on the shipping configuration.
        """
        client = self.base_scenario(
            frang_config="",
            requests=[
                [
                    (":authority", "example.com"),
                    (":path", "/"),
                    (":scheme", "https"),
                    (":method", "DELETE"),
                ],
                [
                    (":authority", "example.com"),
                    (":path", "/"),
                    (":scheme", "https"),
                    (":method", "PUT"),
                ],
                [
                    (":authority", "example.com"),
                    (":path", "/"),
                    (":scheme", "https"),
                    (":method", "OPTIONS"),
                ],
                [
                    (":authority", "example.com"),
                    (":path", "/"),
                    (":scheme", "https"),
                    (":method", "PATCH"),
                ],
                [
                    (":authority", "example.com"),
                    (":path", "/"),
                    (":scheme", "https"),
                    (":method", "TRACE"),
                ],
                [
                    (":authority", "example.com"),
                    (":path", "/"),
                    (":scheme", "https"),
                    (":method", "CONNECT"),
                ],
            ],
            disable_hshc=True,
        )
        self.check_response(client, status_code="403", warning_msg=self.error)

    def test_not_accepted_request_register(self):
        self.disable_deproxy_auto_parser()
        client = self.base_scenario(
            frang_config="http_methods get post;",
            requests=[
                [
                    (":authority", "example.com"),
                    (":path", "/"),
                    (":scheme", "https"),
                    (":method", "gEt"),
                ],
            ],
            disable_hshc=True,
        )
        self.check_response(client, status_code="403", warning_msg=self.error)

    def test_not_accepted_request_with_unknown_method(self):
        client = self.base_scenario(
            frang_config="http_methods get post;",
            requests=[
                [
                    (":authority", "example.com"),
                    (":path", "/"),
                    (":scheme", "https"),
                    (":method", "UNKNOWN"),
                ],
            ],
            disable_hshc=True,
        )
        self.check_response(client, status_code="403", warning_msg=self.error)

    def test_accepted_request_with_unknown_method(self):
        client = self.base_scenario(
            frang_config="http_methods get post unknown;",
            requests=[
                [
                    (":authority", "example.com"),
                    (":path", "/"),
                    (":scheme", "https"),
                    (":method", "UNKNOWN"),
                ],
            ],
            disable_hshc=True,
        )
        self.check_response(client, status_code="200", warning_msg=self.error)

    def test_not_accepted_request_zero_byte(self):
        self.disable_deproxy_auto_parser()
        client = self.base_scenario(
            frang_config="http_methods get post;",
            requests=[
                [
                    (":authority", "example.com"),
                    (":path", "/"),
                    (":scheme", "https"),
                    (":method", b"\x00"),
                ],
            ],
        )
        self.check_response(client, status_code="400", warning_msg="HTTP/2 request dropped:")

    def test_not_accepted_request_owerride(self):
        client = self.base_scenario(
            frang_config="http_methods get put;",
            requests=[self.post_request + [("x-http-method-override", "GET")]],
            disable_hshc=True,
        )
        self.check_response(client, status_code="403", warning_msg=self.error)
