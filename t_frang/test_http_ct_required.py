"""Tests for Frang directive `http_ct_required`."""
from t_frang.frang_test_case import FrangTestCase, H2Config

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"


class FrangHttpCtRequiredTestCase(FrangTestCase):
    error = "frang: Content-Type header field for"

    def test_content_type_set_ok(self):
        """Test with valid header `Content-type`."""
        client = self.base_scenario(
            frang_config="http_ct_required true;",
            requests=[
                "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/html\r\n\r\n",
                "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type:\r\n\r\n",
                "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: invalid\r\n\r\n",
            ],
        )
        self.check_response(client, status_code="200", warning_msg=self.error)

    def test_missing_content_type(self):
        """Test with missing header `Content-type`."""
        client = self.base_scenario(
            frang_config="http_ct_required true;",
            requests=["POST / HTTP/1.1\r\nHost: localhost\r\n\r\n"],
        )
        self.check_response(client, status_code="403", warning_msg=self.error)

    def test_default_http_ct_required(self):
        """Test with default (false) http_ct_required directive."""
        client = self.base_scenario(
            frang_config="",
            requests=["POST / HTTP/1.1\r\nHost: localhost\r\n\r\n"],
        )
        self.check_response(client, status_code="200", warning_msg=self.error)


class FrangHttpCtRequiredH2(H2Config, FrangHttpCtRequiredTestCase):
    def test_content_type_set_ok(self):
        """Test with valid header `Content-type`."""
        client = self.base_scenario(
            frang_config="http_ct_required true;",
            requests=[
                self.post_request + [("content-type", "text/html")],
                self.post_request + [("content-type", "text/html")],  # from dynamic table
                self.post_request + [("content-type", "random")],
                self.post_request + [("content-type", "random")],  # from dynamic table
            ],
            disable_hshc=True,
        )
        self.check_response(client, status_code="200", warning_msg=self.error)

    def test_missing_content_type(self):
        """Test with missing header `Content-type`."""
        client = self.base_scenario(
            frang_config="http_ct_required true;",
            requests=[self.post_request],
            disable_hshc=True,
        )
        self.check_response(client, status_code="403", warning_msg=self.error)

    def test_default_http_ct_required(self):
        """Test with default (false) http_ct_required directive."""
        client = self.base_scenario(
            frang_config="",
            requests=[self.post_request],
            disable_hshc=True,
        )
        self.check_response(client, status_code="200", warning_msg=self.error)
