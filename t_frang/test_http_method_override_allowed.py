"""Tests for Frang directive `http_host_required`."""
from framework import tester
from helpers import dmesg
import pytest


ERROR_MSG = 'Frang limits warning is not shown'
COUNT_WARNINGS_OK = 1
COUNT_WARNINGS_ZERO = 0

RESPONSE_CONTENT = """HTTP/1.1 200 OK\r
Content-Length: 0\r\n
Connection: keep-alive\r\n\r\n
"""

TEMPESTA_CONF = """
cache 0;
listen 80;


frang_limits {
    http_method_override_allowed true;
    http_methods post put get;
}


server ${server_ip}:8000;
"""

WARN = 'frang: restricted HTTP method'
WARN_ERROR = 'frang: restricted overridden HTTP method'
WARN_UNSAFE = 'request dropped: unsafe method override:'

ACCEPTED_REQUEST = """
POST / HTTP/1.1\r
Host: tempesta-tech.com\r
X-HTTP-Method-Override: PUT\r
\r
"""

REQUEST_UNSAFE_OVERRIDE = """
GET / HTTP/1.1\r
Host: tempesta-tech.com\r
X-HTTP-Method-Override: POST\r
\r
"""

NOT_ACCEPTED_REQUEST = """
POST / HTTP/1.1\r
Host: tempesta-tech.com\r
X-HTTP-Method-Override: OPTIONS\r
\r
"""

REQUEST_FALSE_OVERRIDE = """
POST / HTTP/1.1\r
Host: tempesta-tech.com\r
X-HTTP-Method-Override: POST\r
\r
"""

DOUBLE_OVERRIDE = """
POST / HTTP/1.1\r
Host: tempesta-tech.com\r
X-HTTP-Method-Override: PUT\r
Http-Method: GET\r
\r
"""

MULTIPLE_OVERRIDE = """
POST / HTTP/1.1\r
Host: tempesta-tech.com\r
X-HTTP-Method-Override: GET\r
X-HTTP-Method-Override: PUT\r
X-HTTP-Method-Override: GET\r
X-HTTP-Method-Override: GET\r
X-HTTP-Method-Override: PUT\r
X-HTTP-Method-Override: GET\r
\r
"""


class FrangHttpMethodsOverrideTestCase(tester.TempestaTest):


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
        self.start_all()

        deproxy_cl = self.get_client('client')
        deproxy_cl.start()
        deproxy_cl.make_requests(
            ACCEPTED_REQUEST+ 
            REQUEST_FALSE_OVERRIDE+
            DOUBLE_OVERRIDE+
            MULTIPLE_OVERRIDE
        )
        deproxy_cl.wait_for_response(1)
        assert list(p.status for p in deproxy_cl.responses) == ['200', '200', '200', '200'], f'Real status: {list(p.status for p in deproxy_cl.responses)}'
        self.assertEqual(
            4,
            len(deproxy_cl.responses),
        )
        self.assertFalse(
            deproxy_cl.connection_is_closed(),
        )


    def test_not_accepted_request(self):#override methods not allowed by limit http_methods
        self._test_base_scenario(
            request_body=NOT_ACCEPTED_REQUEST,
            expected_warning=WARN_ERROR
        )
    
    
    def test_unsafe_override(self):#should not be allowed to be overridden by unsafe methods
        self._test_base_scenario(
            request_body=REQUEST_UNSAFE_OVERRIDE,
            expected_warning=WARN_UNSAFE
        ) 

    

    def _test_base_scenario(
        self,
        request_body: str,
        expected_warning: str = WARN
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