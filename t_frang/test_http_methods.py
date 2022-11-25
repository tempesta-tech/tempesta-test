"""Tests for Frang directive `http_methods`."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

from t_frang.frang_test_case import FrangTestCase


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
        )
        self.check_response(client, status_code="403", warning_msg=self.error)

    def test_not_accepted_request_register(self):
        client = self.base_scenario(
            frang_config="http_methods get post;",
            requests=["gEt / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n"],
        )
        self.check_response(client, status_code="403", warning_msg=self.error)

    def test_not_accepted_request_zero_byte(self):
        client = self.base_scenario(
            frang_config="http_methods get post;",
            requests=["x0 POST / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n"],
        )
        self.check_response(client, status_code="400", warning_msg="Parser error:")

    def test_not_accepted_request_owerride(self):
        client = self.base_scenario(
            frang_config="http_methods get post;",
            requests=[
                "PUT / HTTP/1.1\r\nHost: tempesta-tech.com\r\nX-HTTP-Method-Override: GET\r\n\r\n"
            ],
        )
        self.check_response(client, status_code="403", warning_msg=self.error)
