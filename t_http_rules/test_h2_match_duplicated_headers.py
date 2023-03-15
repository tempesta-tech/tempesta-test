"""H2 tests for test_match_duplicated_headers.py."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from t_http_rules import test_match_duplicated_headers


class DuplicatedHeadersMatchH2Test(test_match_duplicated_headers.DuplicatedHeadersMatchTest):
    clients = [
        {
            "id": "deproxy",
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
        (":method", "POST"),
    ]

    def test_match_success(self):
        self.start_all_services()

        client = self.get_client("deproxy")
        for header in self.headers_val:
            client.send_request(
                request=(
                    self.request
                    + [
                        ("x-forwarded-for", header[0]),
                        ("x-forwarded-for", header[1]),
                        ("x-forwarded-for", header[2]),
                    ]
                ),
                expected_status_code="200",
            )

    def test_match_fail(self):
        self.start_all_services()

        client = self.get_client("deproxy")
        client.send_request(
            request=(
                self.request
                + [
                    ("x-forwarded-for", "1.2.3.4"),
                ]
            ),
            expected_status_code="403",
        )
