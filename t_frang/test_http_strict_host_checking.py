"""Tests for Frang directive `http_strict_host_checking`."""

from t_frang.frang_test_case import FrangTestCase

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

WARN_UNKNOWN = "frang: Request authority is unknown"
WARN_DIFFER = "frang: Request host from absolute URI differs from Host header for"
WARN_IP_ADDR = "frang: Host header field contains IP address"
WARN_HEADER_HOST = "frang: Request :authority differs from Host for"
WARN_PORT = "Warning: frang: port from host header doesn't match real port"
WARN_PORT_DIFF = "frang: port from host header doesn't match port from uri"


class FrangHostRequiredTestCase(FrangTestCase):
    """
    Tests for non-TLS related checks in 'http_strict_host_checking' directive.

    See TLSMatchHostSni test for other cases.
    """

    clients = [
        {
            "id": "deproxy-1",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
        {
            "id": "deproxy-2",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "81",
        },
    ]

    def test_host_header_set_ok(self):
        """Test with header `host`, success."""
        requests = [
            "GET / HTTP/1.1\r\nHost: tempesta-tech.com:80\r\n\r\n",
            "GET / HTTP/1.1\r\nHost:    tempesta-tech.com     \r\n\r\n",
            "GET http://tempesta-tech.com/ HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n",
            (
                "GET http://tempesta-tech.com/ HTTP/1.1\r\n"
                "Host: tempesta-tech.com\r\n"
                "Forwarded: host=tempesta-tech.com\r\n"
                "Forwarded: host=tempesta1-tech.com\r\n\r\n"
            ),
        ]
        client = self.base_scenario(
            frang_config="http_strict_host_checking true;", requests=requests
        )
        self.check_response(client, status_code="200", warning_msg="frang: ")

    def test_host_header_with_old_proto(self):
        """
        Test with header `host` and http v 1.0.

        Host header in http request below http/1.1. Restricted by
        Tempesta security rules.
        """
        client = self.base_scenario(
            frang_config="http_strict_host_checking true;",
            requests=["GET / HTTP/1.0\r\nHost: tempesta-tech.com\r\n\r\n"],
        )
        self.check_response(
            client,
            status_code="403",
            warning_msg="frang: Host header field in protocol prior to HTTP/1.1",
        )

    def test_host_header_mismatch(self):
        """Test with mismatched header `host`."""
        client = self.base_scenario(
            frang_config="http_strict_host_checking true;",
            requests=["GET http://tempesta-tech.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"],
        )
        self.check_response(client, status_code="403", warning_msg=WARN_DIFFER)

    def test_host_header_mismatch_empty(self):
        """
        Test with Host header is empty.

        Same as `test_host_header_mismatch`, but with empty `host`.
        """
        client = self.base_scenario(
            frang_config="http_strict_host_checking true;",
            requests=["GET http://tempesta-tech.com/ HTTP/1.1\r\nHost: \r\n\r\n"],
        )
        self.check_response(client, status_code="403", warning_msg=WARN_DIFFER)

    def test_host_header_no_port_in_uri(self):
        """Test with default port in uri."""
        client = self.base_scenario(
            frang_config="http_strict_host_checking true;",
            requests=[
                "GET http://tempesta-tech.com/ HTTP/1.1\r\nHost: tempesta-tech.com:80\r\n\r\n"
            ],
        )
        self.check_response(client, status_code="200", warning_msg=WARN_DIFFER)

    def test_host_header_no_port_in_host(self):
        """Test with default port in `Host` header."""
        client = self.base_scenario(
            frang_config="http_strict_host_checking true;",
            requests=[
                "GET http://tempesta-tech.com:80/ HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n"
            ],
        )
        self.check_response(client, status_code="200", warning_msg=WARN_DIFFER)

    def test_host_header_mismatch_port_in_host(self):
        """Test with mismatch port in `Host` header."""
        client = self.base_scenario(
            frang_config="http_strict_host_checking true;",
            requests=[
                "GET http://tempesta-tech.com:81/ HTTP/1.1\r\nHost: tempesta-tech.com:80\r\n\r\n"
            ],
        )
        self.check_response(client, status_code="403", warning_msg=WARN_PORT_DIFF)

    def test_auto_port_mismatch(self):
        """
        After client send a request that has port mismatch in host header,
        it is blocked. Port is defined from implicit values.
        """
        self.set_frang_config(frang_config="http_strict_host_checking true;")

        client = self.get_client("deproxy-2")
        client.start()
        client.make_request("GET / HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n")
        client.wait_for_response()
        self.check_response(client, status_code="403", warning_msg=WARN_PORT)

    def test_auto_port_mismatch_uri(self):
        """
        After client sent a request that has port mismatch in URI,
        it is blocked. Port is defined from implicit values.
        """
        self.set_frang_config(frang_config="http_strict_host_checking true;")

        client = self.get_client("deproxy-2")
        client.start()
        client.make_request(
            "GET http://tempesta-tech.com:80/ HTTP/1.1\r\nHost: tempesta-tech.com\r\n\r\n"
        )
        client.wait_for_response()
        self.check_response(client, status_code="403", warning_msg=WARN_PORT)

    def test_host_header_as_ip(self):
        """Test with header `host` as ip address."""
        client = self.base_scenario(
            frang_config="http_strict_host_checking true;",
            requests=["GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"],
        )
        self.check_response(client, status_code="403", warning_msg=WARN_IP_ADDR)

    def test_host_header_as_ip6(self):
        """Test with header `host` as ip v6 address."""
        client = self.base_scenario(
            frang_config="http_strict_host_checking true;",
            requests=["GET / HTTP/1.1\r\nHost: [20:11:abb::1]:80\r\n\r\n"],
        )
        self.check_response(client, status_code="403", warning_msg=WARN_IP_ADDR)

    def test_disabled_host_http_required(self):
        """Test disable `http_strict_host_checking`."""
        client = self.base_scenario(
            frang_config="http_strict_host_checking false;",
            requests=["GET http://tempesta-tech.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"],
        )
        self.check_response(client, status_code="200", warning_msg="frang: ")

    def test_default_host_http_required(self):
        """Test default (true) `http_strict_host_checking`."""
        client = self.base_scenario(
            frang_config="", requests=["GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"]
        )
        self.check_response(client, status_code="403", warning_msg=WARN_IP_ADDR)


class FrangHostRequiredH2TestCase(FrangTestCase):
    """Tests for checks 'http_strict_host_checking' directive with http2."""

    clients = [
        {
            "id": "deproxy-1",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        },
        {
            "id": "deproxy-2",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "444",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        },
    ]

    tempesta = {
        "config": """
frang_limits {
    %(frang_config)s
}

listen 443 proto=h2;
listen 444 proto=h2;
server ${server_ip}:8000;

tls_match_any_server_name;
tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;

cache 0;
cache_fulfill * *;
block_action attack reply;
block_action error reply;
""",
    }

    timeout = 1

    def test_h2_header_ok(self):
        """Test with header `host`, success."""
        self.set_frang_config(frang_config="http_strict_host_checking true;")
        client = self.get_client("deproxy-1")
        client.start()
        client.parsing = False

        first_headers = [(":authority", "localhost"), (":path", "/")]
        second_headers = [(":path", "/"), ("host", "localhost")]
        third_headers = [(":authority", "localhost"), (":path", "/"), ("host", "localhost")]
        fourth_headers = [
            (":authority", "tempesta-tech.com"),
            (":path", "/"),
            ("forwarded", "host=tempesta-tech.com"),
            ("forwarded", "for=tempesta.com"),
        ]

        header_list = [
            first_headers,
            first_headers,  # as byte
            second_headers,
            second_headers,  # as byte
            third_headers,
            third_headers,  # as byte
            fourth_headers,
            fourth_headers,  # as byte
        ]
        for header in header_list:
            head = [
                (":scheme", "https"),
                (":method", "HEAD"),
            ]
            head.extend(header)
            client.make_request(head)
            self.assertTrue(client.wait_for_response(1))

        self.check_response(client, status_code="200", warning_msg="frang: ")

    def test_h2_host_header_as_ip(self):
        """Test with header `host` as ip address."""
        self._test(
            headers=[
                (":path", "/"),
                ("host", "127.0.0.1"),
            ],
            expected_warning=WARN_IP_ADDR,
        )

    def test_h2_authority_header_as_ip(self):
        """Test with header `host` as ip address."""
        self._test(
            headers=[
                (":path", "/"),
                (":authority", "127.0.0.1"),
            ],
            expected_warning=WARN_IP_ADDR,
        )

    def test_h2_host_header_as_ipv6(self):
        """Test with header `host` as ip v6 address."""
        self._test(
            headers=[
                (":path", "/"),
                ("host", "[20:11:abb::1]:443"),
            ],
            expected_warning=WARN_IP_ADDR,
        )

    def test_h2_authority_header_as_ipv6(self):
        """Test with header `host` as ip v6 address."""
        self._test(
            headers=[
                (":path", "/"),
                (":authority", "[20:11:abb::1]:443"),
            ],
            expected_warning=WARN_IP_ADDR,
        )

    def test_h2_different_host_and_authority_header(self):
        self._test(
            headers=[(":path", "/"), (":authority", "localhost"), ("host", "host")],
            expected_warning=WARN_HEADER_HOST,
        )

    def test_auto_port_mismatch(self):
        """
        After client send a request that has port mismatch in host header,
        it is blocked. Port is defined from implicit values.
        """
        self.set_frang_config(frang_config="http_strict_host_checking true;")

        client = self.get_client("deproxy-2")
        client.start()
        client.make_request(
            [
                (":scheme", "https"),
                (":method", "GET"),
                (":path", "/"),
                (":authority", "tempesta-tech.com"),
            ]
        )
        client.wait_for_response()
        self.check_response(client, status_code="403", warning_msg=WARN_PORT)

    def _test(
        self,
        headers: list,
        expected_warning: str = WARN_UNKNOWN,
        status_code: str = "403",
        disable_hshc: bool = False,
    ):
        """
        Test base scenario for process different requests.
        """
        head = [
            (":scheme", "https"),
            (":method", "GET"),
        ]
        head.extend(headers)

        client = self.base_scenario(
            frang_config="http_strict_host_checking true;",
            requests=[head],
            disable_hshc=disable_hshc,
        )
        self.check_response(client, status_code=status_code, warning_msg=expected_warning)

    def test_disabled_host_http_required(self):
        client = self.base_scenario(
            frang_config="http_strict_host_checking false;",
            requests=[
                [
                    (":scheme", "https"),
                    (":method", "GET"),
                    (":path", "/"),
                    (":authority", "localhost"),
                    ("host", "host"),
                ],
            ],
        )
        self.check_response(client, status_code="200", warning_msg="frang: ")
