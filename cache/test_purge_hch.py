from framework import tester
from helpers import deproxy, tempesta, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"


class HeavyChunkedPurgeTest(tester.TempestaTest):
    # This is a heavy chunked test for ss_skb_chop_head_tail() function in context
    # of rewriting PURGE method as GET, issue #1535
    #
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "keep_original_data": True,
            "response": "static",
            "response_content": """HTTP/1.1 200 OK
Content-Length: 8
Content-Type: text/plain
Connection: keep-alive

THE PAGE
""",
        },
    ]

    tempesta = {
        "config": """
cache 2;
server ${server_ip}:8000;
cache_fulfill * *;
cache_methods GET HEAD;
cache_purge;
cache_purge_acl ${client_ip};

""",
    }

    clients = [
        {"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"},
    ]

    def common_check(
        self,
        request_0="",
        expect_status_0=200,
        request="",
        expect_status=200,
        expect: list = None,
        chunked=False,
    ):
        # Set expect to expected proxied request,
        # to empty string to skip request check and
        # to None to check that request is missing
        deproxy_srv = self.get_server("deproxy")
        deproxy_cl = self.get_client("deproxy")

        self.start_all_services()

        deproxy_cl.send_request(request_0, str(expect_status_0))

        if chunked:
            deproxy_cl.segment_size = 1

        deproxy_cl.send_request(request, str(expect_status))

        frequest: deproxy.Request = deproxy_srv.last_request

        frequest.headers.headers.sort()
        expect.sort()

        self.assertEqual(frequest.method, "GET")
        self.assertEqual(frequest.headers.headers, expect)
        self.assertEqual(frequest.body, "")

    def test_0_purge_non_hch(self):
        # Normal (non heavy-chunked) test
        #
        self.common_check(
            request_0="GET / HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            expect_status_0=200,
            request="PURGE / HTTP/1.1\r\n" "Host: localhost\r\n" "X-Tempesta-Cache: GET\r\n" "\r\n",
            expect_status=200,
            expect=[
                ("Host", "localhost"),
                ("X-Tempesta-Cache", "GET"),
                ("Connection", "keep-alive"),
                ("via", f"1.1 tempesta_fw (Tempesta FW {tempesta.version()})"),
                ("X-Forwarded-For", tf_cfg.cfg.get("Client", "ip")),
            ],
        )

    def test_1_purge_hch(self):
        # Heavy-chunked test
        #
        self.common_check(
            request_0="GET / HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n",
            expect_status_0=200,
            request="PURGE / HTTP/1.1\r\n" "Host: localhost\r\n" "X-Tempesta-Cache: GET\r\n" "\r\n",
            expect_status=200,
            expect=[
                ("Host", "localhost"),
                ("X-Tempesta-Cache", "GET"),
                ("Connection", "keep-alive"),
                ("via", f"1.1 tempesta_fw (Tempesta FW {tempesta.version()})"),
                ("X-Forwarded-For", tf_cfg.cfg.get("Client", "ip")),
            ],
            chunked=True,
        )
