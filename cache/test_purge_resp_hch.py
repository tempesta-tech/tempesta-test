import copy

from framework import tester
from helpers import deproxy, tempesta, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"


class HeavyChunkedPurgeRespTest(tester.TempestaTest):
    # This is another heavy chunked test for ss_skb_chop_head_tail() function
    # in context of rewriting PURGE method as GET, issue #1535, now testing
    # with chunked response
    #
    backends_template = [
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

    BODY_LENGTH = 65536

    def setUp(self):
        self.backends = copy.deepcopy(self.backends_template)
        self.backends[0]["response_content"] = self.generate_content()
        super(HeavyChunkedPurgeRespTest, self).setUp()

    def generate_content(self):
        body = "x" * self.BODY_LENGTH
        return """HTTP/1.1 200 OK
Content-Length: %d
Content-Type: text/plain
Connection: keep-alive

%s""" % (
            self.BODY_LENGTH,
            body,
        )

    def common_check(
        self,
        chunksize=0,
        request_0="",
        expect_status_0=200,
        request="",
        expect_status=200,
        expect: list = None,
    ):
        # Set expect to expected proxied request,
        # to empty string to skip request check and
        # to None to check that request is missing
        deproxy_srv = self.get_server("deproxy")
        deproxy_cl = self.get_client("deproxy")
        deproxy_srv.segment_size = chunksize

        self.start_all_services()

        deproxy_cl.send_request(request_0, str(expect_status_0))

        deproxy_cl.send_request(request, str(expect_status))

        frequest: deproxy.Request = deproxy_srv.last_request

        frequest.headers.headers.sort()
        expect.sort()

        self.assertEqual(frequest.method, "GET")
        self.assertEqual(
            frequest.headers.headers,
            expect,
            "Request sent to backend differs from expected one " "with chunksize = %d" % chunksize,
        )

        self.assertEqual(
            deproxy_cl.last_response.body,
            "",
            "Response body not expected but present " "with chunksize = %d" % chunksize,
        )

    def test_0_purge_resp_non_hch(self):
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

    def test_1_purge_resp_hch(self):
        # Heavy-chunked test, iterative
        #
        response = self.get_server("deproxy").response
        self.iterate_test(
            self.common_check,
            len(response),
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

    def iterate_test(self, test_func, msg_size, *args, **kwargs):
        CHUNK_SIZES = [1, 2, 3, 4, 8, 16, 32, 64, 128, 256, 1500, 9216, 1024 * 1024]
        for i in range(len(CHUNK_SIZES)):
            test_func(CHUNK_SIZES[i], *args, **kwargs)
            if CHUNK_SIZES[i] > msg_size:
                break
