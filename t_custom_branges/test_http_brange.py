"""Functional tests for custom uri brange."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import random

from helpers import deproxy, dmesg
from helpers.remote import CmdError
from test_suite import marks, tester

DEPROXY_CLIENT = {
    "id": "deproxy",
    "type": "deproxy",
    "addr": "${tempesta_ip}",
    "port": "80",
}

DEPROXY_CLIENT_H2 = {
    "id": "deproxy",
    "type": "deproxy_h2",
    "addr": "${tempesta_ip}",
    "port": "443",
    "ssl": True,
}

DEPROXY_SERVER = {
    "id": "deproxy",
    "type": "deproxy",
    "port": "8000",
    "response": "static",
    "response_content": (
        "HTTP/1.1 200 OK\r\n"
        + f"Date: {deproxy.HttpMessage.date_time_string()}\r\n"
        + "Server: deproxy\r\n"
        + "Content-Length: 0\r\n\r\n"
    ),
}

DIRECTIVES = [
    "http_uri_brange",
    "http_token_brange",
    "http_qetoken_brange",
    "http_nctl_brange",
    "http_xff_brange",
    "http_etag_brange",
    "http_cookie_brange",
    "http_ctext_vchar_brange",
]


class TestConfigParsing(tester.TempestaTest):
    tempesta = {
        "config": """
    server ${server_ip}:8000;

    listen 80;
    listen 443 proto=h2;

    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;
    tls_match_any_server_name;

    {directive} {values};
    """
    }

    clients = [DEPROXY_CLIENT_H2]

    backends = [DEPROXY_SERVER]

    def _update_tempesta_config(self, directive: str, characters: str):
        tempesta_conf = self.get_tempesta().config
        tempesta_conf.set_defconfig(
            tempesta_conf.defconfig.format(directive=directive, values=characters)
        )

    @marks.Parameterize.expand(
        [
            marks.Param(name="all_hex", characters="0x00-0x7e"),
            marks.Param(name="all_dec", characters="0-126"),
            marks.Param(name="last", characters="0x21-0x7e 0x00"),
            marks.Param(name="first", characters="0x0a 0x21-0x7e"),
            marks.Param(name="between", characters="0x21-0x40 0x0d 0x41-0x7e"),
        ]
    )
    def test_enable_0x00_0x0a_0x0d(self, name, characters: str):
        """
        Tempesta MUST not start when 0x00, 0x0a, 0x0d bytes are enabled in config.
        They are not allowed by RFC 9113 and cause http/1 parser to fail.
        """
        directive = random.choice(DIRECTIVES)
        self._update_tempesta_config(directive=directive, characters=characters)

        with self.assertRaises(
            CmdError,
            msg=f"Tempesta config parser allowed 0x00 | 0x0a | 0x0d bytes with '{directive}'.",
        ):
            self.start_tempesta()

    def test_uri_brange_combine_dec_and_hex(self):
        """This test checks how Tempesta work when combining dec and hex characters."""
        self._update_tempesta_config(
            directive="http_uri_brange", characters="0x2d-57 0x41-90 0x61-126"
        )

        self.start_all_services()

        client = self.get_client("deproxy")
        client.send_request(
            request=client.create_request(method="GET", headers=[], uri=f"/example\x42"),
            expected_status_code="200",
        )

        self.assertFalse(client.connection_is_closed())

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="etag_brange",
                directive="http_etag_brange",
                characters="0x30-0x39 0x41-0x5a 0x61-0x7a 0x22",
                msg='Tempesta config parser allowed 0x22 (") byte.',
            ),
            marks.Param(
                name="cookie_brange",
                directive="http_cookie_brange",
                characters="0x30-0x39 0x41-0x5a 0x61-0x7a 0x3b 0x3d",
                msg='Tempesta config parser allowed 0x3d ("=") | 0x3b (";") bytes.',
            ),
            marks.Param(
                name="xff_brange",
                directive="http_xff_brange",
                characters="0x30-0x39 0x3a 0x61-0x7a 0x2c",
                msg='Tempesta config parser allowed 0x2c (",") byte.',
            ),
            marks.Param(
                name="token_brange",
                directive="http_token_brange",
                characters="0x61-0x7a 0x2c 0x3b",
                msg='Tempesta config parser allowed 0x2c (",") | 0x3b (";") bytes.',
            ),
            marks.Param(
                name="qetoken_brange",
                directive="http_qetoken_brange",
                characters="0x61-0x7a 0x2c",
                msg='Tempesta config parser allowed 0x2c (",") byte.',
            ),
        ]
    )
    def test_http(self, name, directive, characters, msg):
        self._update_tempesta_config(directive=directive, characters=characters)

        with self.assertRaises(CmdError, msg=msg):
            self.start_tempesta()


@marks.parameterize_class(
    [
        {
            "name": "Http",
            "clients": [DEPROXY_CLIENT],
        },
        {
            "name": "H2",
            "clients": [DEPROXY_CLIENT_H2],
        },
    ]
)
class TestBrange(tester.TempestaTest):
    backends = [DEPROXY_SERVER]

    tempesta = {
        "config": """
server ${server_ip}:8000;

listen 80;
listen 443 proto=h2;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;

{directive} {values};
"""
    }

    def _update_tempesta_config(self, directive: str, characters: str):
        tempesta_conf = self.get_tempesta().config
        tempesta_conf.set_defconfig(
            tempesta_conf.defconfig.format(directive=directive, values=characters)
        )

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="issue_2030",
                # Example from issue #2030:
                # Allow only following characters in URI (no '%'): /a-zA-Z0-9&?:-._=
                custom_uri_branch=(
                    "0x2f 0x41-0x5a 0x61-0x7a 0x30-0x39 0x26 0x3f 0x3a 0x2d 0x2e 0x5f 0x3d"
                ),
                uri="/js/prism.min.js",
                expected_status="200",
            ),
            marks.Param(
                name="blocked_percent",
                custom_uri_branch="0x41-0x7a",
                uri="js%a",
                expected_status="400",
            ),
            marks.Param(
                name="not_blocked_percent",
                custom_uri_branch="0x25 0x41-0x7a",
                uri="/js%a",
                expected_status="200",
            ),
        ]
    )
    def test_http_uri_brange(self, name, custom_uri_branch, uri, expected_status):
        self._update_tempesta_config(directive="http_uri_brange", characters=custom_uri_branch)
        self.start_all_services()
        client = self.get_client("deproxy")

        request = client.create_request(method="GET", uri=uri, headers=[])
        client.send_request(request, expected_status_code=expected_status)

        if expected_status == "200":
            self.assertTrue(client.conn_is_active)
        else:
            self.assertTrue(client.wait_for_connection_close())

    @marks.Parameterize.expand(
        [
            marks.Param(name="0x40_from_0x41_to_0x7e", character="\x40", expected_status="400"),
            marks.Param(name="0x41_from_0x41_to_0x7e", character="\x41", expected_status="200"),
            marks.Param(name="0x7f_from_0x41_to_0x7e", character="\x7f", expected_status="400"),
            marks.Param(name="0x7e_from_0x41_to_0x7e", character="\x7e", expected_status="200"),
            marks.Param(name="disallowed_0x5f", character="\x5f", expected_status="400"),
        ]
    )
    def test_boundary_values(self, name, character, expected_status):
        self._update_tempesta_config(
            directive="http_uri_brange", characters="0x2d-0x39 0x41-0x5a 0x61-0x7e"
        )

        self.start_all_services()

        client = self.get_client("deproxy")
        client.send_request(
            request=client.create_request(method="GET", headers=[], uri=f"/example{character}"),
            expected_status_code=expected_status,
        )

        if expected_status == "200":
            self.assertTrue(client.conn_is_active)
        else:
            self.assertTrue(client.wait_for_connection_close())

    @marks.Parameterize.expand(
        [
            marks.Param(name="disallowed_character", character="\x2b", expected_status="400"),
            marks.Param(name="allowed_character", character="\x2d", expected_status="200"),
        ]
    )
    def test_http_uri_brange_referer_header(self, name, character, expected_status):
        self._update_tempesta_config(
            directive="http_uri_brange", characters="0x2d-0x39 0x41-0x5a 0x61-0x7a"
        )

        self.start_all_services()

        client = self.get_client("deproxy")
        client.send_request(
            request=client.create_request(
                method="GET", headers=[("referer", f"/example{character}")]
            ),
            expected_status_code=expected_status,
        )

        if expected_status == "200":
            self.assertTrue(client.conn_is_active)
        else:
            self.assertTrue(client.wait_for_connection_close())

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="allow",
                etag='"asdfqwerty"',
                expected_status="200",
            ),
            marks.Param(
                name="many_values",
                etag='"asdfqwerty", "sdfrgg"',
                expected_status="200",
            ),
            marks.Param(
                name="allow_weak",
                etag='W/"asdfqwerty"',
                expected_status="200",
            ),
            marks.Param(
                name="allow_all",
                etag="*",
                expected_status="200",
            ),
            marks.Param(
                name="disallow",
                etag='"asdfQWErty"',
                expected_status="400",
            ),
        ]
    )
    def test_http_etag_brange_if_none_match(self, name, etag, expected_status):
        self._update_tempesta_config(directive="http_etag_brange", characters="0x61-0x7a")
        self.start_all_services()

        client = self.get_client("deproxy")
        client.send_request(
            request=client.create_request(method="GET", headers=[("if-none-match", etag)]),
            expected_status_code=expected_status,
        )
        if expected_status == "200":
            self.assertTrue(client.conn_is_active)
        else:
            self.assertTrue(client.wait_for_connection_close())

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="check_value",
                characters="0x30-0x39 0x61-0x7a",
                cookie="id=QWErty",
                expected_status="400",
            ),
            marks.Param(
                name="not_check_name",
                characters="0x30-0x39 0x61-0x7a",
                cookie="ID=qwerty",
                expected_status="200",
            ),
            marks.Param(
                name="allow_many_cookie",
                characters="0x30-0x39 0x41-0x5a 0x61-0x7a",
                cookie="id=qwerty; c2=v2",
                expected_status="200",
            ),
        ]
    )
    def test_http_cookie_brange(self, name, characters, cookie, expected_status):
        self._update_tempesta_config(directive="http_cookie_brange", characters=characters)
        self.start_all_services()

        client = self.get_client("deproxy")
        client.send_request(
            request=client.create_request(method="GET", headers=[("cookie", cookie)]),
            expected_status_code=expected_status,
        )
        if expected_status == "200":
            self.assertTrue(client.conn_is_active)
        else:
            self.assertTrue(client.wait_for_connection_close())

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="allow_ipv4",
                characters="0x30-0x39 0x2e 0x3a 0x61-0x7a",
                ip_="5.10.50.6",
                expected_status="200",
            ),
            marks.Param(
                name="allow_ipv6",
                characters="0x30-0x39 0x2e 0x3a 0x61-0x7a",
                ip_="2001:db8:85a3:8d3:1319:8a2e:370:7348",
                expected_status="200",
            ),
            marks.Param(
                name="allow_many_ip",
                characters="0x30-0x39 0x2e 0x3a 0x61-0x7a",
                ip_="5.10.50.6, 2001:db8:85a3:8d3:1319:8a2e:370:7348",
                expected_status="200",
            ),
            marks.Param(
                name="disallow_ipv4",
                characters="0x30-0x39 0x3a 0x61-0x7a",
                ip_="5.10.50.6",
                expected_status="400",
            ),
            marks.Param(
                name="disallow_ipv6",
                characters="0x30-0x39 0x2e",
                ip_="2001:db8:85a3:8d3:1319:8a2e:370:7348",
                expected_status="400",
            ),
        ]
    )
    def test_http_xff_brange(self, name, characters, ip_, expected_status):
        self._update_tempesta_config(directive="http_xff_brange", characters=characters)
        self.start_all_services()

        client = self.get_client("deproxy")
        client.send_request(
            request=client.create_request(method="GET", headers=[("x-forwarded-for", ip_)]),
            expected_status_code=expected_status,
        )
        if expected_status == "200":
            self.assertTrue(client.conn_is_active)
        else:
            self.assertTrue(client.wait_for_connection_close())

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="allow",
                characters="0x20-0x7a",
                header="Mozilla/5.0 (Windows 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0",
                expected_status="200",
            ),
            marks.Param(
                name="disallow",
                characters="0x20 0x28-0x3b 0x41-0x7a",
                header="Mozilla/5.0 %",
                expected_status="400",
            ),
        ]
    )
    def test_http_ctext_vchar_brange(self, name, characters, header, expected_status):
        self._update_tempesta_config(directive="http_ctext_vchar_brange", characters=characters)
        self.start_all_services()

        client = self.get_client("deproxy")
        client.send_request(
            request=client.create_request(method="GET", headers=[("user-agent", header)]),
            expected_status_code=expected_status,
        )
        if expected_status == "200":
            self.assertTrue(client.conn_is_active)
        else:
            self.assertTrue(client.wait_for_connection_close())

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="positive",
                header_value="unknown=value",
                expected_status="200",
            ),
            marks.Param(
                name="negative",
                header_value="unknown%=value",
                expected_status="400",
            ),
        ]
    )
    def test_http_token_brange(self, name, header_value, expected_status):
        self._update_tempesta_config(directive="http_token_brange", characters="0x41-0x7a")
        self.start_all_services()

        client = self.get_client("deproxy")
        client.parsing = False
        client.send_request(
            request=client.create_request(method="GET", headers=[("cookie", f"{header_value}")]),
            expected_status_code=expected_status,
        )
        if expected_status == "200":
            self.assertTrue(client.conn_is_active)
        else:
            self.assertTrue(client.wait_for_connection_close())

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="positive",
                characters="0x41-0x7a 0x3d",
                cache_control="unknown=value",
                expected_status="200",
            ),
            marks.Param(
                name="disallow_equal",
                characters="0x41-0x7a",
                cache_control="unknown=value",
                expected_status="400",
            ),
            marks.Param(
                name="negative",
                characters="0x41-0x7a 0x3d",
                cache_control="unkno%wn=value%",
                expected_status="400",
            ),
        ]
    )
    def test_http_qetoken_brange(self, name, characters, cache_control, expected_status):
        self._update_tempesta_config(directive="http_qetoken_brange", characters=characters)
        self.start_all_services()

        client = self.get_client("deproxy")
        client.parsing = False
        client.send_request(
            request=client.create_request(method="GET", headers=[("cache-control", cache_control)]),
            expected_status_code=expected_status,
        )
        if expected_status == "200":
            self.assertTrue(client.conn_is_active)
        else:
            self.assertTrue(client.wait_for_connection_close())

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="positive",
                characters="0x20-0x7f",
                date="Mon, 12 Dec 2016 13:59:39 GMT",
                expected_status="200",
            ),
            marks.Param(
                name="negative",
                characters="0x20 0x2c 0x2e 0x30-0x3b 0x41-0x5a 0x61-0x7a",
                date="Mon, 12 Dec 2016% 13:59:39 GMT",
                expected_status="400",
            ),
        ]
    )
    def test_http_nctl_brange_request(self, name, characters, date, expected_status):
        self._update_tempesta_config(directive="http_nctl_brange", characters=characters)
        self.start_all_services()

        client = self.get_client("deproxy")

        client.send_request(
            request=client.create_request(method="GET", headers=[("if-modified-since", date)]),
            expected_status_code=expected_status,
        )

        if expected_status == "200":
            self.assertTrue(client.conn_is_active)
        else:
            self.assertTrue(client.wait_for_connection_close())

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="positive",
                characters="0x20-0x7f",
                date="Mon, 12 Dec 2016 13:59:39 GMT",
                expected_status="200",
            ),
            marks.Param(
                name="negative",
                characters="0x20 0x2c 0x2e 0x30-0x3b 0x41-0x5a 0x61-0x7a",
                date="Mon, 12 Dec 2016% 13:59:39 GMT",
                expected_status="502",
            ),
        ]
    )
    @dmesg.unlimited_rate_on_tempesta_node
    def test_http_nctl_brange_response(self, name, characters, date, expected_status):
        self._update_tempesta_config(directive="http_nctl_brange", characters=characters)
        self.start_all_services()

        client = self.get_client("deproxy")
        server = self.get_server("deproxy")

        for header in ["date", "expires", "last-modified"]:
            with self.subTest(msg=f"subTest with '{header}' header."):
                server.set_response(
                    deproxy.Response.create(
                        status="200",
                        headers=[(header, date), ("content-length", "0")],
                    )
                )
                client.send_request(
                    request=client.create_request(method="GET", headers=[]),
                    expected_status_code=expected_status,
                )
