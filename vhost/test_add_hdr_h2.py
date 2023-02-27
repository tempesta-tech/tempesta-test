"""Functional tests for adding user difined headers in h2 connection."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from vhost import test_add_hdr


class H2Config:
    clients = [
        {
            "id": "deproxy-1",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]
    request = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
    ]


class TestReqAddHeaderH2(H2Config, test_add_hdr.TestReqAddHeader):
    pass


class TestRespAddHeaderH2(H2Config, test_add_hdr.TestRespAddHeader):
    pass


class TestCachedRespAddHeaderH2(H2Config, test_add_hdr.TestCachedRespAddHeader):
    pass


class TestReqSetHeaderH2(H2Config, test_add_hdr.TestReqSetHeader):
    request = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
        ("x-my-hdr", "original text"),
        ("x-my-hdr-2", "other original text"),
    ]


class TestRespSetHeaderH2(H2Config, test_add_hdr.TestRespSetHeader):
    pass


class TestCachedRespSetHeaderH2(H2Config, test_add_hdr.TestCachedRespSetHeader):
    pass


class TestReqDelHeaderH2(H2Config, test_add_hdr.TestReqDelHeader):
    request = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
        ("x-my-hdr", "original text"),
        ("x-my-hdr-2", "other original text"),
    ]


class TestRespDelHeaderH2(H2Config, test_add_hdr.TestRespDelHeader):
    pass


class TestCachedRespDelHeaderH2(H2Config, test_add_hdr.TestCachedRespDelHeader):
    pass
