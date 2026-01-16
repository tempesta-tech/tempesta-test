"""
Tests to verify correctness of matching multiple
similar headers in one request.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

from test_suite import marks, tester


@marks.parameterize_class(
    [
        {
            "name": "Http",
            "clients": [
                {"id": 0, "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"},
                {"id": 1, "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"},
                {"id": 2, "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"},
            ],
        },
        {
            "name": "H2",
            "clients": [
                {
                    "id": 0,
                    "type": "deproxy_h2",
                    "addr": "${tempesta_ip}",
                    "port": "443",
                    "ssl": True,
                },
                {
                    "id": 1,
                    "type": "deproxy_h2",
                    "addr": "${tempesta_ip}",
                    "port": "443",
                    "ssl": True,
                },
                {
                    "id": 2,
                    "type": "deproxy_h2",
                    "addr": "${tempesta_ip}",
                    "port": "443",
                    "ssl": True,
                },
            ],
        },
    ]
)
class TestDuplicatedHeadersMatch(tester.TempestaTest):
    client_type: str
    ssl: bool
    port: int

    backends = [
        {
            "id": 0,
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        }
    ]

    tempesta = {
        "config": """
        listen 80;
        listen 443 proto=h2;
        
        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;
        
        frang_limits {http_strict_host_checking false;}
        block_action attack reply;
        srv_group grp1 {
        server ${server_ip}:8000;
        }
        vhost vh1 {
        proxy_pass grp1;
        }
        http_chain {
        hdr X-Forwarded-For == "1.1.1.1" -> vh1;
        -> block;
        }
        """
    }

    clients = []

    headers_val = [
        ("1.1.1.1", "2.2.2.2", "3.3.3.3"),
        ("2.2.2.2", "1.1.1.1", "3.3.3.3"),
        ("3.3.3.3", "2.2.2.2", "1.1.1.1"),
    ]
    header_name = "X-Forwarded-For"

    def test_match_success(self):
        self.start_all_services()
        for i, headers in enumerate(self.headers_val):
            client = self.get_client(i)
            client.send_request(
                request=client.create_request(
                    method="GET",
                    uri="/",
                    headers=[
                        (self.header_name, headers[0]),
                        (self.header_name, headers[1]),
                        (self.header_name, headers[2]),
                    ],
                ),
                expected_status_code="200",
            )

    def test_match_fail(self):
        self.start_all_services()
        client = self.get_client(0)
        client.send_request(
            request=client.create_request(
                method="GET", uri="/", headers=[(self.header_name, "1.2.3.4")]
            )
        )
