"""H2 tests for http rules. See test_http_rules.py."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from t_http_rules import test_http_rules


class HttpRulesH2(test_http_rules.HttpRules):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]
    requests_n = 2  # client send headers as bytes from dynamic table

    def test_scheduler(self):
        super(HttpRulesH2, self).test_scheduler()

    @staticmethod
    def request_with_options(path, header_name, header_value):
        request = [
            (":path", path),
            (":scheme", "https"),
            (":method", "GET"),
        ]
        if header_name.lower() != "host":
            request.append((":authority", "localhost"))
        if header_name:
            request.append((header_name.lower(), header_value))

        return request
