"""Tests for Frang directive `http_methods`."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from t_frang.frang_test_case import FrangTestCase, H2Config
from test_suite.parameterize import param, parameterize


class FrangHttpMethodsTestCase(FrangTestCase):
    error = "frang: restricted HTTP method"

    def test_accepted_request(self):
        client = self.get_client("deproxy-1")
        client = self.base_scenario(
            frang_config="http_methods get post put;",
            requests=[client.create_request(method="PUT", headers=[])],
        )
        self.check_response(client, status_code="200", warning_msg=self.error)

    def test_not_accepted_request(self):
        client = self.get_client("deproxy-1")
        client = self.base_scenario(
            frang_config="http_methods get put;",
            requests=[client.create_request(method="POST", headers=[])],
            disable_hshc=True,
        )
        self.check_response(client, status_code="403", warning_msg=self.error)

    def test_accepted_request_shipping_cfg(self):
        client = self.get_client("deproxy-1")
        client = self.base_scenario(
            # Task #2058: On the shipping cfg only GET/POST/HEAD allowed.
            frang_config="",
            requests=[
                client.create_request(method="GET", headers=[]),
                client.create_request(method="POST", headers=[]),
                client.create_request(method="HEAD", headers=[]),
            ],
        )
        self.check_response(client, status_code="200", warning_msg=self.error)

    @parameterize.expand(
        [
            param(name="DELETE"),
            param(name="PUT"),
            param(name="OPTIONS"),
            param(name="PATCH"),
            param(name="TRACE"),
            param(name="CONNECT"),
        ]
    )
    def test_not_accepted_request_shipping_cfg(self, name):
        """
        Test that HTTP methods DELETE, PUT, OPTIONS, PATCH, TRACE and CONNECT are not
        accepted on the shipping configuration.
        """
        client = self.get_client("deproxy-1")
        client = self.base_scenario(
            frang_config="",
            requests=[client.create_request(method=name, headers=[])],
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
        client = self.get_client("deproxy-1")
        client = self.base_scenario(
            frang_config="http_methods get post;",
            requests=[client.create_request(method="UNKNOWN", headers=[])],
            disable_hshc=True,
        )
        self.check_response(client, status_code="403", warning_msg=self.error)

    def test_accepted_request_with_unknown_method(self):
        client = self.get_client("deproxy-1")
        client = self.base_scenario(
            frang_config="http_methods get post unknown;",
            requests=[client.create_request(method="UNKNOWN", headers=[])],
            disable_hshc=True,
        )
        self.check_response(client, status_code="200", warning_msg=self.error)

    def test_not_accepted_request_owerride(self):
        client = self.get_client("deproxy-1")
        client = self.base_scenario(
            frang_config="http_methods get post;",
            requests=[
                client.create_request(method="UNKNOWN", headers=[("x-http-method-override", "GET")])
            ],
            disable_hshc=True,
        )
        self.check_response(client, status_code="403", warning_msg=self.error)


class FrangHttpMethodsH2(H2Config, FrangHttpMethodsTestCase):
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
