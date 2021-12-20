from framework import tester
from helpers import tf_cfg, deproxy

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2021 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class CorrectHeadersTest(tester.TempestaTest):
    # This test is created to serve as an exmple or a template for test with
    # iterations of various chunk sizes.
    # It demonstrate how to do thes job in a right way.
    #
    # The test scenario reproduces the fills_hdr_tbl_for_req() test
    # from unit tests.
    #
    # TODO: move the tests to appropriate place (where?).
    #
    backends = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' :
"""HTTP/1.1 200 OK
Content-Length: 0
Connection: keep-alive

"""
        },
    ]

    tempesta = {
        'config' : """
cache 0;
server ${general_ip}:8000;

""",
    }

    clients = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        },
    ]

    def inner_test(self, chunksize, request):
        # This function defines a test scenario itself.
        # In this partucular example the test reproduses
        # the fills_hdr_tbl_for_req() test from unit tests.
        # In your case there could be your own scenario.
        deproxy_srv = self.get_server('deproxy')
        deproxy_srv.start()
        self.start_tempesta()
        deproxy_cl = self.get_client('deproxy')
        deproxy_cl.segment_size = chunksize
        deproxy_cl.start()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))
        deproxy_cl.make_request(request)
        self.assertTrue(deproxy_cl.valid_req_num != 0,
                "Request was not parsed by deproxy client")
        has_resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(has_resp, "Response not received"
                        + "; with chunk size = " + str(chunksize))
        status = int(deproxy_cl.last_response.status)
        self.assertTrue(status == 200, "Wrong status: " + str(status)
                                        +  ", expected: 200"
                        + "; with chunk size = " + str(chunksize))
        self.assertFalse(deproxy_srv.last_request is None,
                           "Request was not send to backend"
                        + "; with chunk size = " + str(chunksize))
	req = deproxy.Request(request)
	hdrs = req.headers.iteritems()
        req2 = deproxy_srv.last_request
        hdrs2 = req2.headers
        for hdr in hdrs:
            v2 = hdrs2.get(hdr[0], "-")
            self.assertTrue(hdr[1] == v2, "Header "+hdr[0]+" mismatch ("
                                          + v2 + " != " + hdr[1] + ")"
                        + "; with chunk size = " + str(chunksize))

    def iterate_test(self, request, *args, **kwargs):
        # This function provides iterations over vrious chunk sizes
        CHUNK_SIZES = [ 1, 2, 3, 4, 8, 16, 32, 64, 128, 256, 1500, 9216, 1024*1024 ]
        for i in range(len(CHUNK_SIZES)):
            self.inner_test(CHUNK_SIZES[i], request, *args, **kwargs)
            if CHUNK_SIZES[i] > len(request):
                break;

    def test_correct_headers(self):
        # This function starts the test with (probably) different
        # parameters
        request = \
            "GET / HTTP/1.1\r\n" \
            "User-Agent: Wget/1.13.4 (linux-gnu)\r\n" \
            "Accept: */*\r\n" \
            "Host: localhost\r\n" \
            "Connection: Keep-Alive\r\n" \
            "X-Custom-Hdr: custom header values\r\n" \
            "Dummy0: 0\r\n" \
            "Dummy1: 1\r\n" \
            "Dummy2: 2\r\n" \
            "Dummy3: 3\r\n" \
            "Dummy4: 4\r\n" \
            "Dummy5: 5\r\n" \
            "Dummy6: 6\r\n" \
            "Content-Type: text/html; charset=iso-8859-1\r\n" \
            "Dummy7: 7\r\n" \
            "Dummy8: 8\r\n" \
            "Dummy9: 9\r\n" \
            "Cache-Control: max-age=1, no-store, min-fresh=30\r\n" \
            "Pragma: no-cache, fooo \r\n" \
            "Transfer-Encoding: compress, gzip, chunked\r\n" \
            "Cookie: session=42; theme=dark\r\n" \
            "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\t \n" \
            "\r\n" \
            "6\r\n" \
            "123456\r\n" \
            "0\r\n" \
            "\r\n"
            # Excluded: "X-Forwarded-For: 127.0.0.1, example.com\r\n"
            # because TFW rewrites it
        self.iterate_test(request)
