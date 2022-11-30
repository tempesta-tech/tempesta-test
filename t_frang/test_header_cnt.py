"""Tests for Frang directive `http_header_cnt`."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

from t_frang.frang_test_case import FrangTestCase

ERROR = "Warning: frang: HTTP headers number exceeded for"


class FrangHttpHeaderCountTestCase(FrangTestCase):
    """Tests for 'http_header_cnt' directive."""

    requests = [
        "POST / HTTP/1.1\r\n"
        "Host: debian\r\n"
        "Content-Type: text/html\r\n"
        "Connection: keep-alive\r\n"
        "Content-Length: 0\r\n\r\n"
    ]

    def test_reaching_the_limit(self):
        """
        We set up for Tempesta `http_header_cnt 2` and
        made request with 4 headers
        """
        client = self.base_scenario(frang_config="http_header_cnt 2;", requests=self.requests)
        self.check_response(client, status_code="403", warning_msg=ERROR)

    def test_not_reaching_the_limit(self):
        """
        We set up for Tempesta `http_header_cnt 4` and
        made request with 4 headers
        """
        client = self.base_scenario(frang_config="http_header_cnt 4;", requests=self.requests)
        self.check_response(client, status_code="200", warning_msg=ERROR)

    def test_not_reaching_the_limit_2(self):
        """
        We set up for Tempesta `http_header_cnt 6` and
        made request with 4 headers
        """
        client = self.base_scenario(frang_config="http_header_cnt 6;", requests=self.requests)
        self.check_response(client, status_code="200", warning_msg=ERROR)

    def test_default_http_header_cnt(self):
        """
        We set up for Tempesta default `http_header_cnt` and
        made request with many headers
        """
        client = self.base_scenario(
            frang_config="",
            requests=[
                "GET / HTTP/1.1\r\n"
                "Host: debian\r\n"
                "Host1: debian\r\n"
                "Host2: debian\r\n"
                "Host3: debian\r\n"
                "Host4: debian\r\n"
                "Host5: debian\r\n"
                "\r\n"
            ],
        )
        self.check_response(client, status_code="200", warning_msg=ERROR)
