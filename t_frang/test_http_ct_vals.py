"""Tests for Frang directive `http_ct_vals`."""
from t_frang.frang_test_case import FrangTestCase

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"


class FrangHttpCtValsTestCase(FrangTestCase):
    error = "frang: restricted Content-Type for"

    def test_content_vals_set_ok(self):
        """Test with valid header `Content-type`."""
        client = self.base_scenario(
            frang_config="http_ct_vals text/html;",
            requests=[
                (
                    "POST / HTTP/1.1\r\nHost: localhost\r\n"
                    "Content-Type: text/html; charset=ISO-8859-4\r\n\r\n"
                ),
                "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/html\r\n\r\n",
            ],
        )
        self.check_response(client, status_code="200", warning_msg=self.error)

    def test_content_vals_set_ok_conf2(self):
        """Test with valid header `Content-type`."""
        client = self.base_scenario(
            frang_config="http_ct_vals text/html text/plain;",
            requests=[
                "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/html\r\n\r\n",
                "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\n\r\n",
            ],
        )
        self.check_response(client, status_code="200", warning_msg=self.error)

    def test_error_content_type(self):
        """Test with invalid header `Content-type`."""
        client = self.base_scenario(
            frang_config="http_ct_vals text/html;",
            requests=["POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\n\r\n"],
        )
        self.check_response(client, status_code="403", warning_msg=self.error)

    def test_error_content_type2(self):
        """Test with http_ct_vals text/*."""
        client = self.base_scenario(
            frang_config="http_ct_vals text/*;",
            requests=["POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/html\r\n\r\n"],
        )
        self.check_response(client, status_code="403", warning_msg=self.error)

    def test_missing_content_type(self):
        """Test with missing header `Content-type`."""
        client = self.base_scenario(
            frang_config="http_ct_vals text/html;",
            requests=["POST / HTTP/1.1\r\nHost: localhost\r\n\r\n"],
        )
        self.check_response(
            client, status_code="403", warning_msg="frang: Content-Type header field for"
        )

    def test_default_http_ct_vals(self):
        """Test with default (disabled) http_ct_vals directive."""
        client = self.base_scenario(
            frang_config="",
            requests=["POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/html\r\n\r\n"],
        )
        self.check_response(client, status_code="200", warning_msg=self.error)
