"""Functional tests for adding user difined headers in h2 connection."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from t_modify_http_headers import test_common_config


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
        (":authority", "localhost"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
    ]


class TestReqAddHeaderH2(H2Config, test_common_config.TestReqAddHeader):
    cache = False
    directive = "req_hdr_add"


class TestRespAddHeaderH2(H2Config, test_common_config.TestReqAddHeader):
    cache = False
    directive = "resp_hdr_add"


class TestCachedRespAddHeaderH2(H2Config, test_common_config.TestReqAddHeader):
    cache = True
    directive = "resp_hdr_add"


class TestReqSetHeaderH2(H2Config, test_common_config.TestReqSetHeader):
    cache = False
    directive = "req_hdr_set"
    request = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
        ("x-my-hdr", "original text"),
        ("x-my-hdr-2", "other original text"),
    ]


class TestRespSetHeaderH2(H2Config, test_common_config.TestRespSetHeader):
    cache = False
    directive = "resp_hdr_set"


class TestCachedRespSetHeaderH2(H2Config, test_common_config.TestRespSetHeader):
    cache = True
    directive = "resp_hdr_set"
