"""Tests for Frang  length related directives."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from t_frang.frang_test_case import FrangTestCase, H2Config
from test_suite import marks


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

    def test_http_hdr_len(self):
        """
        Test 'http_hdr_len'.

        Set up `http_hdr_len 300;` and make request with header greater length

        """
        client = self.base_scenario(
            frang_config="http_hdr_len 300;",
            requests=[f"POST /1234 HTTP/1.1\r\nHost: localhost\r\nX-Long: {'1' * 320}\r\n\r\n"],
        )
        self.check_response(
            client,
            status_code="403",
            warning_msg="frang: HTTP (in-progress )?header length exceeded for",
        )

    def test_http_hdr_len_without_reaching_the_limit(self):
        """
        Test 'http_hdr_len'.

        Set up `http_hdr_len 300; and make request with header 200 length

        """
        client = self.base_scenario(
            frang_config="http_hdr_len 300;",
            requests=[f"POST /1234 HTTP/1.1\r\nHost: localhost\r\nX-Long: {'1' * 200}\r\n\r\n"],
        )
        self.check_response(
            client,
            status_code="200",
            warning_msg="frang: HTTP (in-progress )?header length exceeded for",
        )

    def test_http_hdr_len_without_reaching_the_limit_2(self):
        """
        Test 'http_hdr_len'.

        Set up `http_hdr_len 300; and make request with header 300 length

        """
        client = self.base_scenario(
            frang_config="http_hdr_len 300;",
            requests=[f"POST /1234 HTTP/1.1\r\nHost: localhost\r\nX-Long: {'1' * 292}\r\n\r\n"],
        )
        self.check_response(
            client,
            status_code="200",
            warning_msg="frang: HTTP (in-progress )?header length exceeded for",
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


class FrangLengthH2(H2Config, FrangLengthTestCase):
    def test_uri_len(self):
        """
        Set up `http_uri_len 5;` and make request with uri greater length
        """
        client = self.base_scenario(
            frang_config="http_uri_len 5;",
            requests=[
                [
                    (":authority", "example.com"),
                    (":path", "/123456789"),
                    (":scheme", "https"),
                    (":method", "POST"),
                ]
            ],
        )
        self.check_response(
            client, status_code="403", warning_msg="frang: HTTP URI length exceeded for"
        )

    def test_uri_len_without_reaching_the_limit(self):
        """
        Set up `http_uri_len 5;` and make request with uri 3 length
        """
        request = [
            (":authority", "example.com"),
            (":path", "/12"),
            (":scheme", "https"),
            (":method", "POST"),
        ]
        client = self.base_scenario(
            frang_config="http_uri_len 5;",
            requests=[request, request],  # as string and as byte
            disable_hshc=True,
        )
        self.check_response(
            client, status_code="200", warning_msg="frang: HTTP URI length exceeded for"
        )

    def test_uri_len_on_the_limit(self):
        """
        Set up `http_uri_len 5;` and make request with uri 5 length
        """
        request = [
            (":authority", "example.com"),
            (":path", "/1234"),
            (":scheme", "https"),
            (":method", "POST"),
        ]
        client = self.base_scenario(
            frang_config="http_uri_len 5;",
            requests=[request, request],
            disable_hshc=True,
        )
        self.check_response(
            client, status_code="200", warning_msg="frang: HTTP URI length exceeded for"
        )

    @marks.parameterize.expand(
        [marks.param(name="huffman", huffman=True), marks.param(name="no_huffman", huffman=False)]
    )
    def test_http_hdr_len(self, name, huffman):
        """
        Set up `http_hdr_len 300;` and make request with header greater length
        """
        client = self.base_scenario(
            frang_config="http_hdr_len 300;",
            requests=[self.post_request + [("header", "x" * 320)]],
            huffman=huffman,
        )
        self.check_response(
            client,
            status_code="403",
            warning_msg="frang: HTTP (in-progress )?header length exceeded for",
        )

    @marks.parameterize.expand(
        [marks.param(name="huffman", huffman=True), marks.param(name="no_huffman", huffman=False)]
    )
    def test_http_hdr_len_without_reaching_the_limit(self, name, huffman):
        """
        Set up `http_hdr_len 300; and make request with header 200 length
        """
        client = self.base_scenario(
            frang_config="http_hdr_len 300;",
            requests=[self.post_request + [("header", "x" * 200)]],
            disable_hshc=True,
            huffman=huffman,
        )
        self.check_response(
            client,
            status_code="200",
            warning_msg="frang: HTTP (in-progress )?header length exceeded for",
        )

    @marks.parameterize.expand(
        [marks.param(name="huffman", huffman=True), marks.param(name="no_huffman", huffman=False)]
    )
    def test_http_hdr_len_without_reaching_the_limit_2(self, name, huffman):
        """
        Set up `http_hdr_len 300; and make request with header 300 - 32
        (32 extra bytes are considered the "maximum" overhead that would
        be required to represent each entry in the table) length.
        """
        client = self.base_scenario(
            frang_config="http_hdr_len 300;",
            requests=[self.post_request + [("header", "x" * 262)]],
            disable_hshc=True,
            huffman=huffman,
        )
        self.check_response(
            client,
            status_code="200",
            warning_msg="frang: HTTP (in-progress )?header length exceeded for",
        )

    def test_body_len(self):
        """
        Set up `http_body_len 10;` and make request with body greater length
        """
        client = self.base_scenario(
            frang_config="http_body_len 10;",
            requests=[(self.post_request, "x" * 20)],
        )
        self.check_response(
            client, status_code="403", warning_msg="frang: HTTP body length exceeded for"
        )

    def test_body_len_without_reaching_the_limit_zero_len(self):
        """
        Set up `http_body_len 10;` and make request with body 0 length
        """
        client = self.base_scenario(
            frang_config="http_body_len 10;",
            requests=[self.post_request],
            disable_hshc=True,
        )
        self.check_response(
            client, status_code="200", warning_msg="frang: HTTP body length exceeded for"
        )

    def test_body_len_without_reaching_the_limit(self):
        """
        Set up `http_body_len 10;` and make request with body shorter length
        """
        client = self.base_scenario(
            frang_config="http_body_len 10;",
            requests=[(self.post_request, "x" * 10)],
        )
        self.check_response(
            client, status_code="200", warning_msg="frang: HTTP body length exceeded for"
        )
