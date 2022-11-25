"""Tests for Frang  length related directives."""
from t_frang.frang_test_case import FrangTestCase

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"


class FrangLengthTestCase(FrangTestCase):
    """Tests for length related directives."""

    def test_uri_len(self):
        """
        Test 'http_uri_len'.

        Set up `http_uri_len 5;` and make request with uri greater length

        """
        client = self.base_scenario(
            frang_config="http_uri_len 5;",
            requests=["POST /123456789 HTTP/1.1\r\nHost: localhost\r\n\r\n"],
        )
        self.check_response(
            client, status_code="403", warning_msg="frang: HTTP URI length exceeded for"
        )

    def test_uri_len_without_reaching_the_limit(self):
        """
        Test 'http_uri_len'.

        Set up `http_uri_len 5;` and make request with uri 1 length

        """
        client = self.base_scenario(
            frang_config="http_uri_len 5;", requests=["POST / HTTP/1.1\r\nHost: localhost\r\n\r\n"]
        )
        self.check_response(
            client, status_code="200", warning_msg="frang: HTTP URI length exceeded for"
        )

    def test_uri_len_on_the_limit(self):
        """
        Test 'http_uri_len'.

        Set up `http_uri_len 5;` and make request with uri 5 length

        """
        client = self.base_scenario(
            frang_config="http_uri_len 5;",
            requests=["POST /1234 HTTP/1.1\r\nHost: localhost\r\n\r\n"],
        )
        self.check_response(
            client, status_code="200", warning_msg="frang: HTTP URI length exceeded for"
        )

    def test_field_len(self):
        """
        Test 'http_field_len'.

        Set up `http_field_len 300;` and make request with header greater length

        """
        client = self.base_scenario(
            frang_config="http_field_len 300;",
            requests=[f"POST /1234 HTTP/1.1\r\nHost: localhost\r\nX-Long: {'1' * 320}\r\n\r\n"],
        )
        self.check_response(
            client, status_code="403", warning_msg="frang: HTTP field length exceeded for"
        )

    def test_field_without_reaching_the_limit(self):
        """
        Test 'http_field_len'.

        Set up `http_field_len 300; and make request with header 200 length

        """
        client = self.base_scenario(
            frang_config="http_field_len 300;",
            requests=[f"POST /1234 HTTP/1.1\r\nHost: localhost\r\nX-Long: {'1' * 200}\r\n\r\n"],
        )
        self.check_response(
            client, status_code="200", warning_msg="frang: HTTP field length exceeded for"
        )

    def test_field_without_reaching_the_limit_2(self):
        """
        Test 'http_field_len'.

        Set up `http_field_len 300; and make request with header 300 length

        """
        client = self.base_scenario(
            frang_config="http_field_len 300;",
            requests=[f"POST /1234 HTTP/1.1\r\nHost: localhost\r\nX-Long: {'1' * 292}\r\n\r\n"],
        )
        self.check_response(
            client, status_code="200", warning_msg="frang: HTTP field length exceeded for"
        )

    def test_body_len(self):
        """
        Test 'http_body_len'.

        Set up `http_body_len 10;` and make request with body greater length

        """
        client = self.base_scenario(
            frang_config="http_body_len 10;",
            requests=[
                f"POST /1234 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 20\r\n\r\n{'x' * 20}"
            ],
        )
        self.check_response(
            client, status_code="403", warning_msg="frang: HTTP body length exceeded for"
        )

    def test_body_len_without_reaching_the_limit_zero_len(self):
        """
        Test 'http_body_len'.

        Set up `http_body_len 10;` and make request with body 0 length

        """
        client = self.base_scenario(
            frang_config="http_body_len 10;",
            requests=[f"POST /1234 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"],
        )
        self.check_response(
            client, status_code="200", warning_msg="frang: HTTP body length exceeded for"
        )

    def test_body_len_without_reaching_the_limit(self):
        """
        Test 'http_body_len'.

        Set up `http_body_len 10;` and make request with body shorter length

        """
        client = self.base_scenario(
            frang_config="http_body_len 10;",
            requests=[
                f"POST /1234 HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10\r\n\r\n{'x' * 10}"
            ],
        )
        self.check_response(
            client, status_code="200", warning_msg="frang: HTTP body length exceeded for"
        )
