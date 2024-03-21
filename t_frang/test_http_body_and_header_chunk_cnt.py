"""Functional tests for `http_header_chunk_cnt` and `http_body_chunk_cnt`  directive"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework.deproxy_client import DeproxyClient
from t_frang.frang_test_case import FrangTestCase, H2Config

CLIENT = {
    "id": "deproxy-1",
    "type": "deproxy",
    "addr": "${tempesta_ip}",
    "port": "80",
    "segment_gap": 100,  # ms
}


class HttpHeaderChunkCnt(FrangTestCase):
    error = "Warning: frang: HTTP header chunk count exceeded"
    clients = [CLIENT]

    requests = [
        "POST / HTTP/1.1\r\n",
        "Host: localhost\r\n",
        "Content-type: text/plain\r\n" "Content-Length: 0\r\n\r\n",
    ]

    def base_scenario(self, frang_config: str, requests: list[str], **kwargs):
        self.set_frang_config("\n".join([frang_config, "http_strict_host_checking false;"]))

        client = self.get_client("deproxy-1")
        client.parsing = False
        client.start()
        for data in requests:
            client.make_request(data)
        client.valid_req_num = 1
        client.wait_for_response()
        return client

    def test_chunk_cnt_ok(self):
        """Set up `http_header_chunk_cnt 3;` and make request with 3 header chunk"""
        self.disable_deproxy_auto_parser()
        client = self.base_scenario(
            frang_config="http_header_chunk_cnt 3;",
            requests=self.requests,
        )
        self.check_response(client, "200", self.error)

    def test_chunk_cnt_ok_2(self):
        """Set up `http_header_chunk_cnt 5;` and make request with 3 header chunk"""
        self.disable_deproxy_auto_parser()
        client = self.base_scenario(
            frang_config="http_header_chunk_cnt 5;",
            requests=self.requests,
        )
        self.check_response(client, "200", self.error)

    def test_chunk_cnt_invalid(self):
        """Set up `http_header_chunk_cnt 2;` and make request with 3 header chunk"""
        self.disable_deproxy_auto_parser()
        client = self.base_scenario(frang_config="http_header_chunk_cnt 2;", requests=self.requests)
        self.check_response(client, "403", self.error)


class HttpBodyChunkCnt(HttpHeaderChunkCnt):
    error = "Warning: frang: HTTP body chunk count exceeded"
    clients = [CLIENT]

    requests = [
        "POST / HTTP/1.1\r\nHost: debian\r\nContent-type: text/plain\r\nContent-Length: 4\r\n\r\n",
        "1",
        "2",
        "3",
        "4",
    ]

    def test_chunk_cnt_ok(self):
        """Set up `http_body_chunk_cnt 4;` and make request with 4 body chunk"""
        self.disable_deproxy_auto_parser()
        client = self.base_scenario(frang_config="http_body_chunk_cnt 4;", requests=self.requests)
        self.check_response(client, "200", self.error)

    def test_chunk_cnt_ok_2(self):
        """Set up `http_body_chunk_cnt 10;` and make request with 4 body chunk"""
        self.disable_deproxy_auto_parser()
        client = self.base_scenario(frang_config="http_body_chunk_cnt 10;", requests=self.requests)
        self.check_response(client, "200", self.error)

    def test_chunk_cnt_invalid(self):
        """Set up `http_body_chunk_cnt 3;` and make request with 4 body chunk"""
        self.disable_deproxy_auto_parser()
        client = self.base_scenario(frang_config="http_body_chunk_cnt 3;", requests=self.requests)
        self.check_response(client, "403", self.error)


class HttpHeaderChunkCntH2Base(H2Config, FrangTestCase, base=True):
    segment_size: int

    def base_scenario(self, frang_config: str, requests: list, disable_hshc: bool = False):
        self.set_frang_config(
            "\n".join(
                [frang_config] + (["http_strict_host_checking false;"] if disable_hshc else [])
            )
        )

        client = self.get_client("deproxy-1")
        client.parsing = False
        client.start()

        client.update_initial_settings()
        client.send_bytes(client.h2_connection.data_to_send())
        client.wait_for_ack_settings()
        client.h2_connection.clear_outbound_data_buffer()

        client.segment_size = self.segment_size
        client.make_request(requests[0], huffman=False)
        client.wait_for_response(3)
        return client


class HttpHeaderChunkCntH2(HttpHeaderChunkCntH2Base, HttpHeaderChunkCnt):
    requests = [
        [
            (":authority", "localhost"),
            (":path", "/"),
            (":scheme", "https"),
            (":method", "POST"),
            ("12345", "x" * 5),
        ]
    ]
    #
    # header frame = 9 header bytes + 27 header block bytes, headers are in 2-4 chunks
    segment_size = 9  # headers - 27 bytes (3 chunks)


class HttpBodyChunkCntH2(HttpHeaderChunkCntH2Base, HttpBodyChunkCnt):
    """Tempesta counts only bytes of body."""

    requests = [
        (
            [
                (":authority", "example.com"),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "POST"),
            ],
            "x" * 4,
        ),
    ]
    segment_size = 1  # request body - 4 bytes (4 chunks)
