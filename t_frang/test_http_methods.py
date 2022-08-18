"""Tests for Frang directive `http_methods`."""
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
    http_methods get;
}


server ${server_ip}:8000;
"""

WARN = 'frang: restricted HTTP method'

ACCEPTED_REQUEST = """
GET / HTTP/1.1\r
Host: tempesta-tech.com\r
\r
"""

NOT_ACCEPTED_REQUEST = """
POST / HTTP/1.1\r
Host: tempesta-tech.com\r
"""


class FrangHttpMethodsTestCase(tester.TempestaTest):

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

    def test_accepted_request(self):
        """Test with content_type, success."""
        self.start_all()

        deproxy_cl = self.get_client('client')
        deproxy_cl.start()
        deproxy_cl.make_requests(
            ACCEPTED_REQUEST,
        )
        deproxy_cl.wait_for_response(1)
        assert list(p.status for p in deproxy_cl.responses) == ['200']
        self.assertEqual(
            1,
            len(deproxy_cl.responses),
        )
        self.assertFalse(
            deproxy_cl.connection_is_closed(),
        )

    def test_not_accepted_request(self):
        self._test_base_scenario(
            request_body=NOT_ACCEPTED_REQUEST,
        )

    def _test_base_scenario(
        self,
        request_body: str,
        expected_warning: str = WARN,
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