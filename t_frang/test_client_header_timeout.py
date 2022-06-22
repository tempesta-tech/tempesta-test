"""Tests for Frang directive `client_header_timeout`."""
from framework import tester
from helpers import dmesg

RESPONSE_CONTENT = """
HTTP/1.1 200 OK\r\n
Content-Length: 0\r\n
Connection: keep-alive\r\n\r\n
"""

REQUEST_SUCCESS = """
GET / HTTP/1.1\r
Host: tempesta-tech.com\r
\r
GET / HTTP/1.1\r
Host:    tempesta-tech.com     \r
\r
GET http://tempesta-tech.com/ HTTP/1.1\r
Host: tempesta-tech.com\r
\r
GET http://user@tempesta-tech.com/ HTTP/1.1\r
Host: tempesta-tech.com\r
\r
"""

TEMPESTA_CONF = """
cache 0;
listen 80;

frang_limits {
    client_header_timeout 1;
}

server ${server_ip}:8000;
"""


class ClientHeaderTimeoutTestCase(tester.TempestaTest):
    """Tests 'client_header_timeout' directive."""

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

    def test_host_header_set_ok(self):  # TODO
        """Test with header `host`, success."""
        self.start_all()

        deproxy_cl = self.get_client('client')
        deproxy_cl.start()
        deproxy_cl.make_requests(
            REQUEST_SUCCESS,
        )
        deproxy_cl.wait_for_response()
