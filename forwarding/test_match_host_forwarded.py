"""
Tests for verifying correctness of matching
all host headers (URI, Host, Forwarded).
"""

from framework import tester
from framework.parameterize import param, parameterize

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestMatchHost(tester.TempestaTest):
    clients = [{"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"}]

    backends = [
        {
            "id": 0,
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        },
        {
            "id": 1,
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        },
        {
            "id": 2,
            "type": "deproxy",
            "port": "8002",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        },
    ]

    tempesta = {
        "config": """
        block_action attack reply;
        srv_group grp1 {
        server ${server_ip}:8000;
        }
        srv_group grp2 {
        server ${server_ip}:8001;
        }
        srv_group grp3 {
        server ${server_ip}:8002;
        }
        vhost shop {
        proxy_pass grp1;
        }
        vhost wiki {
        proxy_pass grp2;
        }
        vhost app {
        proxy_pass grp3;
        }
        http_chain {
        hdr host == "testapp.com" -> app;
        hdr forwarded == "host=testshop.com" -> shop;
        host == "badhost.com" -> block;
        host == "testshop.com" -> shop;
        host == "testwiki.com" -> wiki;
        host == "testapp.com" -> app;
        host == [fd80::1cb2:ad12:ca16:98ef]:8080 -> app;
        -> block;
        }
        """
    }

    @parameterize.expand(
        [
            param(
                name=1,
                uri="http://testshop.com",  # <--must be matched by "host eq"
                host="testwiki.com",
                headers=[("Forwarded", "host=testapp.com")],
                status="200",
                sid=0,
            ),
            param(
                name=2,
                uri="http://testshop.com",  # <--must be matched by "host eq"
                host="badhost.com",
                headers=[("Forwarded", "host=badhost.com")],
                status="200",
                sid=0,
            ),
            param(
                name=3,
                uri="http://testshop.com",
                host="testapp.com",  # <--must be matched by "hdr host == testapp.com"
                headers=[("Forwarded", "host=testwiki.com")],
                status="200",
                sid=2,
            ),
            param(
                name=4,
                uri="http://badhost.com",
                host="badhost.com",
                headers=[("Forwarded", "host=testshop.com")],  # must be matched by "hdr forwarded"
                status="200",
                sid=0,
            ),
            param(
                name=5,
                uri="http://badhost.com",
                host="badhost.com",
                headers=[
                    ("Forwarded", "host=unkhost.com"),
                    ("Forwarded", "host=testshop.com"),  # <--must be matched by "hdr forwarded"
                ],
                status="200",
                sid=0,
            ),
            param(
                name=6,
                uri="/foo",
                host="testwiki.com",  # <--must be matched by "host eq"
                headers=[("Forwarded", "host=forwarded.host.ignored")],
                status="200",
                sid=1,
            ),
            param(
                name=7,
                uri="/foo",
                host="TesTaPp.cOm",  # <--must be matched by "host eq"
                headers=[("Forwarded", "HoSt=forwarded.host.ignored")],
                status="200",
                sid=2,
            ),
            param(
                name=7,
                uri="/foo",
                host="[fd80::1cb2:ad12:ca16:98ef]:8080",  # <--must be matched by "host eq"
                headers=[("Forwarded", 'host="forwarded.host.ignored"')],
                status="200",
                sid=2,
            ),
            param(
                name=8,
                uri="/foo",
                host="badhost.com",
                headers=[("Forwarded", "host=forwarded.host.ignored")],
                status="403",
                sid=0,
            ),
            param(
                name=9,
                uri="/foo",
                host="unkhost.com",
                headers=[],
                status="403",
                sid=0,
            ),
        ]
    )
    def test(self, name, uri, host, headers, status, sid):
        """
        Send requests with different hosts
        and check correctness of forwarding
        comparing id of the last request on
        client and server.
        """
        self.start_all_services()
        client = self.get_client("deproxy")
        server = self.get_server(sid)

        client.send_request(
            client.create_request(
                method="GET", uri=uri, authority=host, headers=headers + [("x-req-id", str(name))]
            ),
            expected_status_code=status,
        )

        if status == "200":
            self.assertEqual(int(server.last_request.headers.get("x-req-id")), name)
