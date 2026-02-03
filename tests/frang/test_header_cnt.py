"""Tests for Frang directive `http_header_cnt`."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import time
from ssl import SSLWantWriteError

from hpack import HeaderTuple
from hyperframe.frame import HeadersFrame

from framework.test_suite import marks
from tests.frang.frang_test_case import FrangTestCase, H2Config

ERROR = "Warning: frang: HTTP headers count exceeded for"


class FrangHttpHeaderCountTestCase(FrangTestCase):
    """Tests for 'http_header_cnt' directive."""

    requests = [
        "POST / HTTP/1.1\r\n"
        "Host: debian\r\n"
        "Content-Type: text/html\r\n"
        "Connection: keep-alive\r\n"
        "Content-Length: 0\r\n\r\n"
    ]

    request_with_many_headers = [
        "GET / HTTP/1.1\r\n"
        "Host: debian\r\n"
        "Host1: debian\r\n"
        "Host2: debian\r\n"
        "Host3: debian\r\n"
        "Host4: debian\r\n"
        "Host5: debian\r\n"
        "\r\n"
    ]

    def test_reaching_the_limit(self):
        """
        We set up for Tempesta `http_header_cnt 2` and
        made request with 4 headers
        """
        client = self.base_scenario(
            frang_config="http_header_cnt 2;",
            requests=self.requests,
            disable_hshc=True,
        )
        self.check_response(client, status_code="403", warning_msg=ERROR)

    def test_not_reaching_the_limit(self):
        """
        We set up for Tempesta `http_header_cnt 4` and
        made request with 4 headers
        """
        client = self.base_scenario(
            frang_config="http_header_cnt 4;",
            requests=self.requests,
            disable_hshc=True,
        )
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
        client = self.base_scenario(frang_config="", requests=self.request_with_many_headers)
        self.check_response(client, status_code="200", warning_msg=ERROR)


class FrangHttpHeaderCountH2(H2Config, FrangHttpHeaderCountTestCase):
    requests = [
        [
            (":authority", "example.com"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "POST"),
        ],
    ]

    requests_with_same_header = [
        [
            (":authority", "example.com"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "POST"),
            ("header1", "value1"),
        ],
        [
            (":authority", "example.com"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "POST"),
            ("header1", "value1"),
            ("header1", "value1"),
            ("header1", "value1"),
            ("header1", "value1"),
        ],
    ]

    request_with_many_headers = [
        [
            (":authority", "example.com"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "POST"),
        ],
    ]
    request_with_many_headers[0].extend([(f"header{step}", f"value{step}") for step in range(10)])

    @marks.Parameterize.expand(
        [marks.Param(name="huffman", huffman=True), marks.Param(name="no_huffman", huffman=False)]
    )
    def test_reaching_limit_headers_as_bytes(self, name, huffman):
        """
        We set up for Tempesta `http_header_cnt 5` and
        made request with 4 headers as index from dynamic table.
        """
        client = self.base_scenario(
            frang_config="http_header_cnt 5;",
            requests=self.requests_with_same_header,
            huffman=huffman,
        )
        self.assertEqual(
            client.responses[0].status,
            "200",
            "Tempesta block a request with 5 (4 pseudo + 1) headers for http_header_cnt 5.",
        )
        self.check_last_response(client, status_code="403", warning_msg=ERROR)

    @marks.Parameterize.expand(
        [marks.Param(name="huffman", huffman=True), marks.Param(name="no_huffman", huffman=False)]
    )
    def test_not_reaching_limit_headers_as_bytes(self, name, huffman):
        """
        We set up for Tempesta `http_header_cnt 8` and
        made request with 8 headers (duplicate headers taken into account)
        as index from dynamic table.
        """
        client = self.base_scenario(
            frang_config="http_header_cnt 8;",
            requests=self.requests_with_same_header,
            disable_hshc=True,
            huffman=huffman,
        )
        self.check_response(client, status_code="200", warning_msg=ERROR)

    @marks.Parameterize.expand(
        [marks.Param(name="huffman", huffman=True), marks.Param(name="no_huffman", huffman=False)]
    )
    def test_not_reaching_the_limit_2(self, name, huffman):
        """
        We set up for Tempesta `http_header_cnt 8` and
        made request with 8 headers (duplicate headers taken into account)
        as index from dynamic table.
        """
        client = self.base_scenario(
            frang_config="http_header_cnt 8;",
            requests=self.requests_with_same_header,
            disable_hshc=True,
            huffman=huffman,
        )
        self.check_response(client, status_code="200", warning_msg=ERROR)

    @marks.Parameterize.expand(
        [marks.Param(name="huffman", huffman=True), marks.Param(name="no_huffman", huffman=False)]
    )
    def test_default_http_header_cnt(self, name, huffman):
        """
        We set up for Tempesta default `http_header_cnt` and
        made request with many headers as index from dynamic table.
        """
        client = self.base_scenario(
            frang_config="",
            requests=self.requests_with_same_header,
            disable_hshc=True,
        )
        self.check_response(client, status_code="200", warning_msg=ERROR)

    @marks.Parameterize.expand(
        [marks.Param(name="huffman", huffman=True), marks.Param(name="no_huffman", huffman=False)]
    )
    def test_hpack_bomb(self, name, huffman):
        """
        Cause HPACK bomb, probably with many connections, and make sure that
        http_header_cnt limit prevents the attack.
        """
        self.set_frang_config("http_header_cnt 6;")

        client = self.get_client("deproxy-1")
        client.parsing = False
        client.start()
        client.make_request(
            request=self.post_request + [HeaderTuple(b"a", b"a" * 4000)],
            end_stream=False,
            huffman=huffman,
        )

        # wait for Tempesta to save header in dynamic table
        time.sleep(0.5)

        # Generate and send attack frames.
        now = time.time()
        while now + 2 > time.time():
            time.sleep(0.1)
            client.stream_id += 2
            stream = client.init_stream_for_send(client.stream_id)
            encoded_headers = client.h2_connection.encoder.encode(self.post_request)
            attack_frame = HeadersFrame(
                stream_id=client.stream_id,
                data=(encoded_headers + (b"\xbe" * (2**6))),
            )
            attack_frame.flags.add("END_HEADERS")

            try:
                client.send(attack_frame.serialize())
            except SSLWantWriteError:
                continue
            except:
                break

        self.check_response(client, status_code="403", warning_msg=ERROR)
