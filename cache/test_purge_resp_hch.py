from framework import tester
from helpers import tf_cfg, deproxy, tempesta
import copy

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2021 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class HeavyChunkedPurgeRespTest(tester.TempestaTest):
    # This is another heavy chunked test for ss_skb_chop_head_tail() function
    # in context of rewriting PURGE method as GET, issue #1535, now testing
    # with chunked response
    #
    backends_template = [
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

    #BODY_LENGTH = 4000 # OK NON HCH
    #BODY_LENGTH = 5000 # FAIL
    BODY_LENGTH = 65536 # FAIL

    def setUp(self):
        self.backends = copy.deepcopy(self.backends_template)
        self.backends[0]['response_content'] = self.generate_content()
        super(HeavyChunkedPurgeTest, self).setUp()

    def generate_content(self):
        body = "x"*self.BODY_LENGTH
        return (
"""HTTP/1.1 200 OK
Content-Length: %d
Content-Type: text/plain
Connection: keep-alive

%s
""" % (self.BODY_LENGTH, body)
        )

    def common_check(self, chunksize=0, request_0='', expect_status_0=200,
                           request='', expect_status=200, expect=''):
        # Set expect to expected proxied request,
        # to empty string to skip request check and
        # to None to check that request is missing
        deproxy_srv = self.get_server('deproxy')
        deproxy_srv.segment_size = chunksize
        #print (deproxy_srv.response)
        deproxy_srv.start()
        self.start_tempesta()
        deproxy_cl = self.get_client('deproxy')
        deproxy_cl.start()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))
        deproxy_cl.make_request(request_0)
        has_resp = deproxy_cl.wait_for_response(timeout=10)
        self.assertTrue(has_resp,
               "Response not received, with chunksize = %d" % chunksize)
        status = int(deproxy_cl.last_response.status)
        self.assertTrue(status == expect_status_0,
               "Wrong status: %d , expected: %d with chunksize = %d" %
                   (status, expect_status, chunksize))
        deproxy_cl.make_request(request)
        has_resp = deproxy_cl.wait_for_response(timeout=10)
        self.assertTrue(has_resp,
               "Response not received, with chunksize = %d" % chunksize)
        status = int(deproxy_cl.last_response.status)
        self.assertTrue(status == expect_status,
               "Wrong status: %d , expected: %d with chunksize = %d" %
                   (status, expect_status, chunksize))
        frequest = deproxy_srv.last_request
        if expect is None:
            self.assertTrue(frequest is None,
                   "Request was unexpectedly sent to backend " \
                   "with chunksize = %d" % chunksize)
        elif expect:
            self.assertTrue(
                frequest.original_data == expect,
                   "Request sent to backend differs from expected one " \
                   "with chunksize = %d" % chunksize)

    def test_0_purge_resp_non_hch(self):
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



    def test_1_purge_resp_hch(self):
    	# Heavy-chunked test, iterative
    	#
        response = self.get_server('deproxy').response
        self.iterate_test(self.common_check, len(response),
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

    def iterate_test(self, test_func, msg_size, *args, **kwargs):
        CHUNK_SIZES = [ 1, 2, 3, 4, 8, 16, 32, 64, 128, 256, 1500, 9216,
                        1024*1024 ]
        for i in range(len(CHUNK_SIZES)):
            test_func(CHUNK_SIZES[i], *args, **kwargs)
            if CHUNK_SIZES[i] > msg_size:
                break;

