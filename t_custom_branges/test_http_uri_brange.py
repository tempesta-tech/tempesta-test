"""Functional tests for custom uri brange."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester
from framework.parameterize import param, parameterize, parameterize_class
from helpers.deproxy import HttpMessage

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


class HttpUriBrangeBase(tester.TempestaTest):
    backends = [
        {
            "id": "server-1",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + f"Date: {HttpMessage.date_time_string()}\r\n"
                + "Server: deproxy\r\n"
                + "Content-Length: 0\r\n\r\n"
            ),
        },
    ]

    tempesta_tmpl = """
		server ${server_ip}:8000;

		listen 80;
		listen 443 proto=h2;

		tls_certificate ${tempesta_workdir}/tempesta.crt;
		tls_certificate_key ${tempesta_workdir}/tempesta.key;
		tls_match_any_server_name;

		http_uri_brange %s;
	"""


@parameterize_class(
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
class TestUriBrange(HttpUriBrangeBase):
    @parameterize.expand(
        [
            param(
                name="issue_2030",
                # Example from issue #2030:
                # Allow only following characters in URI (no '%'): /a-zA-Z0-9&?:-._=
                custom_uri_branch="0x2f 0x41-0x5a 0x61-0x7a 0x30-0x39 0x26 0x3f 0x3a 0x2d 0x2e 0x5f 0x3d",
                uri="/js/prism.min.js",
                expected_status="200",
            ),
            param(
                name="blocked_percent",
                custom_uri_branch="0x41-0x7a",
                uri="js%a",
                expected_status="400",
            ),
            param(
                name="not_blocked_percent",
                custom_uri_branch="0x25 0x41-0x7a",
                uri="/js%a",
                expected_status="200",
            ),
        ]
    )
    def test(self, name, custom_uri_branch, uri, expected_status):
        self.tempesta = {
            "config": self.tempesta_tmpl % custom_uri_branch,
        }
        tester.TempestaTest.setUp(self)
        self.start_all_services()
        client = self.get_client("deproxy")

        request = client.create_request(method="GET", uri=uri, headers=[])
        client.send_request(request, expected_status_code=expected_status)
