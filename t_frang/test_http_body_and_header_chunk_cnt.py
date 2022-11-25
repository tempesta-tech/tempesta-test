"""Functional tests for `http_header_chunk_cnt` and `http_body_chunk_cnt`  directive"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

from t_frang.frang_test_case import FrangTestCase


class HttpHeaderChunkCnt(FrangTestCase):
    error = "Warning: frang: HTTP header chunk count exceeded"

    requests = [
        "POST / HTTP/1.1\r\n",
        "Host: localhost\r\n",
        "Content-type: text/plain\r\n" "Content-Length: 0\r\n\r\n",
    ]

    def test_header_chunk_cnt_ok(self):
        """Set up `http_header_chunk_cnt 3;` and make request with 3 header chunk"""
        client = self.base_scenario(frang_config="http_header_chunk_cnt 3;", requests=self.requests)
        self.check_response(client, "200", self.error)

    def test_header_chunk_cnt_ok_2(self):
        """Set up `http_header_chunk_cnt 5;` and make request with 3 header chunk"""
        client = self.base_scenario(frang_config="http_header_chunk_cnt 5;", requests=self.requests)
        self.check_response(client, "200", self.error)

    def test_header_chunk_cnt_invalid(self):
        """Set up `http_header_chunk_cnt 2;` and make request with 3 header chunk"""
        client = self.base_scenario(frang_config="http_header_chunk_cnt 2;", requests=self.requests)
        self.check_response(client, "403", self.error)


class HttpBodyChunkCnt(FrangTestCase):
    error = "Warning: frang: HTTP body chunk count exceeded"

    requests = [
        "POST / HTTP/1.1\r\nHost: debian\r\nContent-type: text/plain\r\nContent-Length: 4\r\n\r\n",
        "1",
        "2",
        "3",
        "4",
    ]

    def test_body_chunk_cnt_ok(self):
        """Set up `http_body_chunk_cnt 4;` and make request with 4 body chunk"""
        client = self.base_scenario(frang_config="http_body_chunk_cnt 4;", requests=self.requests)
        self.check_response(client, "200", self.error)

    def test_body_chunk_cnt_ok_2(self):
        """Set up `http_body_chunk_cnt 10;` and make request with 4 body chunk"""
        client = self.base_scenario(frang_config="http_body_chunk_cnt 10;", requests=self.requests)
        self.check_response(client, "200", self.error)

    def test_body_chunk_cnt_invalid(self):
        """Set up `http_body_chunk_cnt 3;` and make request with 4 body chunk"""
        client = self.base_scenario(frang_config="http_body_chunk_cnt 3;", requests=self.requests)
        self.check_response(client, "403", self.error)
