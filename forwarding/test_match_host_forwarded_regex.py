"""
Tests for verifying correctness of matching
all host headers (URI, Host, Forwarded).
"""

from test_suite import marks, tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"


class BaseRegexMatcher(tester.TempestaTest, base=True):

    backends = [
        {
            "id": 0,
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 1\r\n\r\n0",
        },
        {
            "id": 1,
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 1\r\n\r\n1",
        },
        {
            "id": 2,
            "type": "deproxy",
            "port": "8002",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 1\r\n\r\n2",
        },
        {
            "id": 3,
            "type": "deproxy",
            "port": "8003",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 1\r\n\r\n3",
        },
    ]

    blocked_response_status = "403"
    success_response_status = "200"


@marks.parameterize_class(
    [
        {
            "name": "Http",
            "clients": [
                {"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"}
            ],
        },
        {
            "name": "H2",
            "clients": [
                {
                    "id": "deproxy",
                    "type": "deproxy_h2",
                    "addr": "${tempesta_ip}",
                    "port": "443",
                    "ssl": True,
                }
            ],
        },
    ]
)
class TestMatchLocations(BaseRegexMatcher):

    backends = BaseRegexMatcher.backends + [
        {
            "id": 4,
            "type": "deproxy",
            "port": "8004",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 1\r\n\r\n4",
        }
    ]

    tempesta = {
        "config": """

        listen 80;
        listen 443 proto=h2;
        
        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;
        access_log off;

        block_action attack reply;
        frang_limits {http_strict_host_checking false;}
        srv_group grp1 {
        server ${server_ip}:8000;
        }
        srv_group grp2 {
        server ${server_ip}:8001;
        }
        srv_group grp3 {
        server ${server_ip}:8002;
        }
        srv_group grp4 {
        server ${server_ip}:8003;
        }
        srv_group grp5 {
        server ${server_ip}:8004;
        }

        vhost test {
            proxy_pass grp5;
            location ~ "/^/article/id/[0-9]+/" {
                proxy_pass grp2;
            }
            location ~ "/shop/" {
                proxy_pass grp1;
            }
            location ~ "/wiki/" {
                proxy_pass grp2;
            }
        }

        vhost work {
            proxy_pass grp5;
            location ~ "/shop/i" {
                proxy_pass grp3;
            }
            location ~ "/wiki/" {
                proxy_pass grp4;
            }
        }

        http_chain {
            host ~ "/test/i" -> test;
            host ~ "/work/i" -> work;
            -> block;
        }
        """
    }

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="host_testwiki_uri_testwiki",
                uri="/testwiki",  # <--The second must be matched by "location ~ "/wiki/"" of vhost test.
                host="testwiki.com",  # <--The first must be matched by "host ~ "/test/" -> test".
                block=False,
                sid=1,
            ),
            marks.Param(
                name="host_testapp_uri_article_id_num",
                uri="/article/id/1234",  # <--The second must be matched by "location ~ "^/article/id/[0-9]+"" of vhost test.
                host="testapp.com",  # <--The first must be matched by "host ~ "/test/" -> test".
                block=False,
                sid=1,
            ),
            marks.Param(
                name="host_testapp_uri_article_id_alph",
                uri="/article/id/abc",  # <-- Not matched by location, therefore route to vhost test instead location.
                host="testapp.com",  # <--The first must be matched by "host ~ "/test/" -> test".
                block=False,
                sid=4,
            ),
            marks.Param(
                name="host_testapp_uri_testshop",
                uri="/testshop",  # <--The second must be matched by "location ~ "/shop/"" of vhost test.
                host="testapp.com",  # <--The first must be matched by "host ~ "/test/" -> test".
                block=False,
                sid=0,
            ),
            marks.Param(  # <--The second is not matched with anything.
                name="host_testapp_uri_testapp",
                uri="/testapp",
                host="testapp.com",  # <--The first must be matched by "host ~ "/test/" -> test".
                block=False,
                sid=4,
            ),
            marks.Param(
                name="host_WorkShop_uri_testwiki",
                uri="/testwiki",  # <--The second must be matched by "location ~ "/wiki/"" of vhost work.
                host="WorkShop.com",  # <--The first must be matched by "host ~ "/work/" -> work".
                block=False,
                sid=3,
            ),
            marks.Param(
                name="host_WorkWiki_uri_testshop",
                uri="/testshop",  # <--The second must be matched by "location ~ "/shop/"" of vhost work.
                host="WorkWiki.com",  # <--The first must be matched by "host ~ "/work/" -> work".
                block=False,
                sid=2,
            ),
            marks.Param(  # <--The second is not matched with anything.
                name="host_workapp_uri_testapp",
                uri="/testapp",
                host="workapp.com",  # <--The first must be matched by "host ~ "/work/" -> work".
                block=False,
                sid=4,
            ),
            marks.Param(
                name="host_ordinary_uri_ignored",
                uri="/ignored",
                host="ordinary.com",  # <--Must fail all matches and be blocked.
                block=True,
                sid=0,
            ),
        ]
    )
    def test(self, name, uri, host, block, sid):
        """
        Send requests with different URI and headers
        and check correctness of forwarding
        by compare last response body with sid of
        whaiting server.
        """
        self.start_all_services()
        client = self.get_client("deproxy")
        request = client.create_request(method="GET", uri=uri, authority=host, headers=[])
        client.send_request(request)
        if not block:
            last_response_status = client.last_response.status
            self.assertEqual(self.success_response_status, last_response_status)
            last_body = client.last_response.body
            self.assertEqual(str(sid), last_body)
        else:
            last_response_status = client.last_response.status
            self.assertEqual(self.blocked_response_status, last_response_status)


@marks.parameterize_class(
    [
        {
            "name": "Http",
            "clients": [
                {"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"}
            ],
        },
        {
            "name": "H2",
            "clients": [
                {
                    "id": "deproxy",
                    "type": "deproxy_h2",
                    "addr": "${tempesta_ip}",
                    "port": "443",
                    "ssl": True,
                }
            ],
        },
    ]
)
class TestMatchHost(BaseRegexMatcher):

    tempesta = {
        "config": """

        listen 80;
        listen 443 proto=h2;

        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;
        access_log off;

        block_action attack reply;
        frang_limits {http_strict_host_checking false;}
        srv_group grp1 {
        server ${server_ip}:8000;
        }
        srv_group grp2 {
        server ${server_ip}:8001;
        }
        srv_group grp3 {
        server ${server_ip}:8002;
        }
        srv_group grp4 {
        server ${server_ip}:8003;
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
        vhost doc {
        proxy_pass grp4;
        }
        http_chain {
        hdr host ~ "/stap/" -> app;
        host ~ "/dho/" -> block;
        host ~ "/tsho/" -> shop;
        hdr User-Agent ~ "/ill/" -> wiki;
        hdr forwarded ~ "/t=se/" -> doc;
        hdr forwarded ~ "/host\./" -> app;
        host ~ "/app|ad12:ca16/i" -> app;
        hdr test_raw ~ "/raw_value/" -> app;
        -> block;
        }
        """
    }

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="host_testshop_uri_none",
                uri="/",
                host="testshop.com",  # <--Must be matched by "host ~ "/tsho/"".
                headers=[
                    ("Forwarded", "host=testapp.com"),
                ],
                block=False,
                sid=0,
            ),
            marks.Param(
                name="host_testapp_uri_none",
                uri="/",
                host="testapp.com",  # <--Must be matched by "hdr host ~ "/stap/"".
                headers=[],
                block=False,
                sid=2,
            ),
            marks.Param(
                name="raw_header_choose_host",
                uri="/",
                host="testraw.headers",
                headers=[
                    (
                        "test_raw",
                        "test_raw_value",
                    )  # <--Must be matched by "hdr host ~ "/raw_value/"".
                ],
                block=False,
                sid=2,
            ),
            marks.Param(
                name="raw_header_duplicate_choose_host",
                uri="/",
                host="testraw.headers",
                headers=[
                    ("test_raw", "raw_val"),
                    ("test_raw", "value1"),
                    (
                        "test_raw",
                        "test_raw_value",
                    ),  # <--Must be matched by "hdr host ~ "/raw_value/"".
                ],
                block=False,
                sid=2,
            ),
            marks.Param(  # <--Must be blocked.
                name="host_bobhost_uri_none",
                uri="/",
                host="bobhost.com",
                headers=[],
                block=True,
                sid=0,
            ),
            marks.Param(
                name="host_testwiki_uri_foo",
                uri="/foo",
                host="testwiki.com",
                headers=[
                    ("User-Agent", "Mozilla")
                ],  # <--Must be matched by "hdr User-Agent ~ "/ill/".
                block=False,
                sid=1,
            ),
            marks.Param(
                name="host_testwiki_uri_foo_upper_case",
                uri="/foo",
                host="testwiki.com",
                headers=[
                    ("User-Agent", "MoziLla")
                ],  # <--Must not be matched by "hdr User-Agent ~ "/ill/".
                block=True,
                sid=0,
            ),
            marks.Param(
                name="host_TesTaPp_uri_foo_fwd_hhh",
                uri="/foo",
                host="TesTaPp.cOm",
                headers=[
                    ("Forwarded", "host=sent.hhh.ignored"),
                ],  # <--Must be matched by "hdr forwarded ~ "/t=se/"".
                block=False,
                sid=3,
            ),
            marks.Param(
                name="host_TesTaPp_uri_foo_fwd_host",
                uri="/foo",
                host="TesTaPp.cOm",
                headers=[
                    ("Forwarded", "host=forwarded.host.ignored"),
                ],  # <--Must be matched by "hdr forwarded ~ "/host./"".
                block=False,
                sid=2,
            ),
            marks.Param(
                name="host_TesTaPp_uri_foo_fwd_hhh2",
                uri="/foo",
                host="TesTaPp.cOm",  # <--Must be matched by "host ~ "/app|ad12:ca16/"".
                headers=[
                    ("Forwarded", "host=forwarded.hhh.ignored"),
                ],
                block=False,
                sid=2,
            ),
            marks.Param(
                name="host_fd80_uri_foo",
                uri="/foo",
                host="[fd80::1cb2:ad12:ca16:98ef]:8080",  # <--Must be matched by "host ~ "/app|ad12:ca16/"".
                headers=[
                    ("Forwarded", "host=forwarded.hhh.ignored"),
                ],
                block=False,
                sid=2,
            ),
            marks.Param(  # <--must be blocked
                name="host_badhost_uri_foo",
                uri="/foo",
                host="badhost.com",
                headers=[
                    ("Forwarded", "host=forwarded.host.ignored"),
                ],
                block=True,
                sid=0,
            ),
            marks.Param(  # <--must be blocked
                name="host_unkhost_uri_foo",
                uri="/foo",
                host="unkhost.com",
                headers=[],
                block=True,
                sid=0,
            ),
        ]
    )
    def test(self, name, uri, host, headers, block, sid):
        """
        Send requests with different URI and headers
        and check correctness of forwarding
        by compare last response body with sid of
        whaiting server.
        """
        self.start_all_services()
        client = self.get_client("deproxy")
        request = client.create_request(method="GET", uri=uri, authority=host, headers=headers)
        client.send_request(request)
        if not block:
            last_response_status = client.last_response.status
            self.assertEqual(self.success_response_status, last_response_status)
            last_body = client.last_response.body
            self.assertEqual(str(sid), last_body)
        else:
            last_response_status = client.last_response.status
            self.assertEqual(self.blocked_response_status, last_response_status)
