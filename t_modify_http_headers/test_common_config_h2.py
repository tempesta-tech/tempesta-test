"""Functional tests for adding user difined headers in h2 connection."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from t_modify_http_headers import test_common_config
from t_modify_http_headers.utils import H2Config


class TestReqAddHeaderH2(H2Config, test_common_config.TestReqAddHeader):
    pass


class TestRespAddHeaderH2(H2Config, test_common_config.TestRespAddHeader):
    pass


class TestCachedRespAddHeaderH2(H2Config, test_common_config.TestCachedRespAddHeader):
    pass


class TestReqSetHeaderH2(H2Config, test_common_config.TestReqSetHeader):
    request = [
        (":authority", "example.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
        ("x-my-hdr", "original text"),
        ("x-my-hdr-2", "other original text"),
    ]


class TestRespSetHeaderH2(H2Config, test_common_config.TestRespSetHeader):
    pass


class TestCachedRespSetHeaderH2(H2Config, test_common_config.TestCachedRespSetHeader):
    pass
