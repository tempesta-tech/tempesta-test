"""Tests for Frang directive `http_trailer_split_allowed`."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

from t_frang.frang_test_case import FrangTestCase

WARN = "frang: HTTP field appear in header and trailer"

REQUEST_WITH_TRAILER = (
    "GET / HTTP/1.1\r\n"
    "Host: debian\r\n"
    "HdrTest: testVal\r\n"
    "Transfer-Encoding: gzip, chunked\r\n"
    "\r\n"
    "4\r\n"
    "test\r\n"
    "0\r\n"
    "HdrTest: testVal\r\n"
    "\r\n"
)


class FrangHttpTrailerSplitLimitOnTestCase(FrangTestCase):
    def test_accepted_request(self):
        client = self.base_scenario(
            frang_config="http_trailer_split_allowed true;",
            requests=[
                REQUEST_WITH_TRAILER,
                (
                    "GET / HTTP/1.1\r\n"
                    "Host: debian\r\n"
                    "HdrTest: testVal\r\n"
                    "Transfer-Encoding: chunked\r\n"
                    "\r\n"
                    "4\r\n"
                    "test\r\n"
                    "0\r\n"
                    "\r\n"
                ),
                "POST / HTTP/1.1\r\nHost: debian\r\nHdrTest: testVal\r\n\r\n",
            ],
            timeout = 60
        )
        self.check_response(client, status_code="200", warning_msg=WARN)

    def test_disable_trailer_split_allowed(self):
        """Test with disable `http_trailer_split_allowed` directive."""
        client = self.base_scenario(
            frang_config="http_trailer_split_allowed false;",
            requests=["POST / HTTP/1.1\r\nHost: debian\r\nHdrTest: testVal\r\n\r\n"],
        )
        self.check_response(client, status_code="200", warning_msg=WARN)

    def test_default_trailer_split_allowed(self):
        """Test with default (false) `http_trailer_split_allowed` directive."""
        client = self.base_scenario(frang_config="", requests=[REQUEST_WITH_TRAILER])
        self.check_response(client, status_code="403", warning_msg=WARN)
