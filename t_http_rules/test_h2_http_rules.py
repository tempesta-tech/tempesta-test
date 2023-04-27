"""H2 tests for http rules. See test_http_rules.py."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from t_http_rules import test_http_rules
from t_http_rules.test_http_rules import TestHostBase


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


class TestH2Host(TestHostBase):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    def test_hdr_host_in_authority_header(self):
        """:authority header is not hdr host."""
        self.send_request_and_check_server_request(
            request=[
                (":authority", "natsys-lab.com"),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
            ],
            server_id=2,
        )

    def test_host_in_authority_header(self):
        """:authority header is host."""
        self.send_request_and_check_server_request(
            request=[
                (":authority", "tempesta-tech.com"),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
            ],
            server_id=0,
        )

    def test_host_in_host_header(self):
        """Host header is host if :authority header is not present."""
        self.send_request_and_check_server_request(
            request=[
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
                ("host", "tempesta-tech.com"),
            ],
            server_id=0,
        )

    def test_different_authority_and_host_headers(self):
        """:authority header has first priority."""
        self.send_request_and_check_server_request(
            request=[
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
                (":authority", "badhost.com"),
                ("host", "tempesta-tech.com"),
            ],
            server_id=2,
        )

    def test_host_in_forwarded_header(self):
        """Forwarded header does not override host."""
        self.send_request_and_check_server_request(
            request=[
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
                (":authority", "badhost"),
                ("forwarded", "host=tempesta-tech.com"),
            ],
            server_id=2,
        )

    def test_hdr_host_in_forwarded_header(self):
        """Forwarded header does not override hdr host."""
        self.send_request_and_check_server_request(
            request=[
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
                (":authority", "badhost"),
                ("forwarded", "host=natsys-lab.com"),
            ],
            server_id=2,
        )
