from framework import tester
from helpers import dmesg


COUNT_WARNINGS_OK = 1


ERROR_MSG = 'Frang limits warning is not shown'

RESPONSE_CONTENT = """HTTP/1.1 200 OK\r
Content-Length: 0\r\n
Connection: keep-alive\r\n\r\n
"""

TEMPESTA_CONF = """
cache 0;
listen 80;

frang_limits {
    http_ct_vals text/html;
}  

server ${server_ip}:8000;
"""


WARN_UNKNOWN = 'frang: Request authority is unknown'
WARN_EMPTY = 'frang: Content-Type header field for 127.0.0.1 is missed'
WARN_ERROR = 'frang: restricted Content-Type'

REQUEST_SUCCESS = """
POST / HTTP/1.1\r
Host: tempesta-tech.com\r
Content-Type: text/html
\r
"""

REQUEST_EMPTY_CONTENT_TYPE = """
POST / HTTP/1.1\r
Host: tempesta-tech.com
\r
"""
REQUEST_ERROR = """
POST / HTTP/1.1\r
Host: tempesta-tech.com\r
Content-Type: text/plain
\r
"""



class FrangHttpCtValsTestCase(tester.TempestaTest):

    clients = [
        {
            'id': 'client',
            'type': 'deproxy',
            'addr': '${tempesta_ip}',
            'port': '80',
        },
    ]

    backends = [
        {
            'id': '0',
            'type': 'deproxy',
            'port': '8000',
            'response': 'static',
            'response_content': RESPONSE_CONTENT,
        },
    ]

    tempesta = {
        'config': TEMPESTA_CONF,
    }

    def setUp(self):
        """Set up test."""
        super().setUp()
        self.klog = dmesg.DmesgFinder(ratelimited=False)

    def start_all(self):
        """Start all requirements."""
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        srv = self.get_server('0')
        self.assertTrue(
            srv.wait_for_connections(timeout=1),
        )

    def test_content_vals_set_ok(self):
        self.start_all()

        deproxy_cl = self.get_client('client')
        deproxy_cl.start()
        deproxy_cl.make_requests(
            REQUEST_SUCCESS,
        )
        deproxy_cl.wait_for_response()
        assert list(p.status for p in deproxy_cl.responses) == ['200']
        self.assertEqual(
            1,
            len(deproxy_cl.responses),
        )
        self.assertFalse(
            deproxy_cl.connection_is_closed(),
        )


    def test_error_content_type(self):
        self._test_base_scenario(
            request_body=REQUEST_ERROR,
            expected_warning=WARN_ERROR
        )


    def test_empty_content_type(self):
        """Test with empty header `host`."""
        self._test_base_scenario(
            request_body=REQUEST_EMPTY_CONTENT_TYPE,
            expected_warning=WARN_EMPTY
        )



    def _test_base_scenario(
        self,
        request_body: str,
        expected_warning: str = WARN_UNKNOWN,
    ):
        """
        Test base scenario for process different requests.

        Args:
            request_body (str): request body
            expected_warning (str): expected warning in logs
        """
        self.start_all()

        deproxy_cl = self.get_client('client')
        deproxy_cl.start()
        deproxy_cl.make_requests(
            request_body,
        )
        deproxy_cl.wait_for_response()

        self.assertEqual(
            0,
            len(deproxy_cl.responses),
        )
        self.assertTrue(
            deproxy_cl.connection_is_closed(),
        )
        self.assertEqual(
            self.klog.warn_count(expected_warning),
            COUNT_WARNINGS_OK,
            ERROR_MSG,
        )
