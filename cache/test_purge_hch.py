from framework import tester
from helpers import tf_cfg, deproxy, tempesta

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class HeavyChunkedPurgeTest(tester.TempestaTest):
    # This is a heavy chunked test for ss_skb_chop_head_tail() function in context
    # of rewriting PURGE method as GET, issue #1535
    #
    backends = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'port' : '8000',
            'keep_original_data' : True,
            'response' : 'static',
            'response_content' :
"""HTTP/1.1 200 OK
Content-Length: 8
Content-Type: text/plain
Connection: keep-alive

THE PAGE
"""
        },
    ]

    tempesta = {
        'config' : """
cache 2;
server ${general_ip}:8000;
cache_fulfill * *;
cache_methods GET HEAD;
cache_purge;
cache_purge_acl ${client_ip};

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

    def common_check(self, request_0='', expect_status_0=200,
                           request='', expect_status=200, expect='', 
                           chunked=False):
        # Set expect to expected proxied request,
        # to empty string to skip request check and
        # to None to check that request is missing
        deproxy_srv = self.get_server('deproxy')
        deproxy_srv.start()
        self.start_tempesta()
        deproxy_cl = self.get_client('deproxy')
        deproxy_cl.start()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))

        deproxy_cl.make_request(request_0)
        has_resp = deproxy_cl.wait_for_response(timeout=5)

        self.assertTrue(has_resp, "Response not received")
        status = int(deproxy_cl.last_response.status)
        self.assertTrue(status == expect_status_0,
               "Wrong status: %d, expected: %d" % (status, expect_status_0))

        if chunked:
            deproxy_cl.segment_size = 1
        deproxy_cl.make_request(request)
        has_resp = deproxy_cl.wait_for_response(timeout=5)

        self.assertTrue(has_resp, "Response not received")
        status = int(deproxy_cl.last_response.status)
        self.assertTrue(status == expect_status,
               "Wrong status: %d, expected: %d" % (status, expect_status))

        frequest = deproxy_srv.last_request
        if expect is None:
            self.assertTrue(frequest is None,
                   "Request was unexpectedly sent to backend")
        elif expect:
            self.assertTrue(
                frequest.original_data == expect,
                "Request sent to backend differs from expected one")

    def test_0_purge_non_hch(self):
    	# Normal (non heavy-chunked) test
    	#
        self.common_check(
          request_0 = 'GET / HTTP/1.1\r\n' \
                      'Host: localhost\r\n' \
                      '\r\n',
          expect_status_0 = 200,
          request = 'PURGE / HTTP/1.1\r\n' \
                    'Host: localhost\r\n' \
                    'X-Tempesta-Cache: GET\r\n' \
                    '\r\n',
          expect_status = 200,
          expect = 'GET / HTTP/1.1\r\n' \
                   'Host: localhost\r\n' \
                   'X-Tempesta-Cache: GET\r\n' \
                   'X-Forwarded-For: 127.0.0.1\r\n' \
                   'via: 1.1 tempesta_fw (Tempesta FW %s)\r\n' \
                   'Connection: keep-alive\r\n' \
                   '\r\n' % tempesta.version()
        )

    def test_1_purge_hch(self):
    	# Heavy-chunked test
    	#
        self.common_check(
          request_0 = 'GET / HTTP/1.1\r\n' \
                      'Host: localhost\r\n' \
                      '\r\n',
          expect_status_0 = 200,
          request = 'PURGE / HTTP/1.1\r\n' \
                    'Host: localhost\r\n' \
                    'X-Tempesta-Cache: GET\r\n' \
                    '\r\n',
          expect_status = 200,
          expect = 'GET / HTTP/1.1\r\n' \
                   'Host: localhost\r\n' \
                   'X-Tempesta-Cache: GET\r\n' \
                   'X-Forwarded-For: 127.0.0.1\r\n' \
                   'via: 1.1 tempesta_fw (Tempesta FW %s)\r\n' \
                   'Connection: keep-alive\r\n' \
                   '\r\n' % tempesta.version(),
          chunked = True
        )

