"""Tests for Frang directive `http_trailer_split_allowed`."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

from hyperframe.frame import ContinuationFrame, HeadersFrame

from test_suite import marks
from tests.frang.frang_test_case import FrangTestCase, H2Config

WARN = "frang: HTTP field appear in header and trailer"

REQUEST_WITH_TRAILER = (
    "POST / HTTP/1.1\r\n"
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
                    "POST / HTTP/1.1\r\n"
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


class TestFrangHttpTrailerSplitAllowedH2(H2Config, FrangTestCase):
    @marks.Parameterize.expand(
        [
            marks.Param(
                name="accepted_request",
                config="http_trailer_split_allowed true;\n",
                expected_status="200",
            ),
            marks.Param(
                name="disable_trailer_split_allowed",
                config="http_trailer_split_allowed false;\n",
                expected_status="403",
            ),
            marks.Param(
                name="default_trailer_split_allowed",
                config="",
                expected_status="403",
            ),
        ]
    )
    def test(self, name, config: str, expected_status: str):
        self.set_frang_config(f"{config}http_strict_host_checking false;")

        client = self.get_client("deproxy-1")
        client.start()
        client.make_request(
            request=client.create_request(
                method="POST", headers=[("trailer", "x-my-hdr"), ("x-my-hdr", "value")]
            ),
            end_stream=False,
        )

        tf = HeadersFrame(
            stream_id=client.stream_id,
            data=client.h2_connection.encoder.encode([("x-my-hdr", "value")]),
            flags=["END_STREAM"],
        )
        cf = ContinuationFrame(
            stream_id=client.stream_id,
            data=client.h2_connection.encoder.encode([("x-my-hdr", "value")]),
            flags=["END_HEADERS"],
        )
        client.send_bytes(data=tf.serialize() + cf.serialize(), expect_response=True)

        self.assertTrue(client.wait_for_response())
        self.check_response(client, status_code=expected_status, warning_msg=WARN)
