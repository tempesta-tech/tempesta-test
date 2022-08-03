"""Tests for Frang directive `http_host_required`."""
from framework import tester
from helpers import dmesg


CURL_CODE_OK = 0
CURL_CODE_BAD = 1
COUNT_WARNINGS_OK = 1
COUNT_WARNINGS_ZERO = 0

ERROR_MSG = 'Frang limits warning is not shown'
ERROR_CURL = 'Curl return code is not `0`: {0}.'

RESPONSE_CONTENT = """HTTP/1.1 200 OK\r
Content-Length: 0\r\n
Connection: keep-alive\r\n\r\n
"""

TEMPESTA_CONF = """
cache 0;
listen 80;

frang_limits {
    http_host_required;
}

server ${server_ip}:8000;
"""

WARN_OLD_PROTO = 'frang: Host header field in protocol prior to HTTP/1.1'
WARN_UNKNOWN = 'frang: Request authority is unknown'
WARN_DIFFER = 'frang: Request authority in URI differs from host header'
WARN_IP_ADDR = 'frang: Host header field contains IP address'
WARN_HEADER_MISSING = 'failed to parse request:'
WARN_HEADER_MISMATCH = 'Bad TLS alert'

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

REQUEST_EMPTY_HOST = """
GET / HTTP/1.1\r
Host: \r
\r
"""

REQUEST_MISMATCH = """
GET http://user@tempesta-tech.com/ HTTP/1.1\r
Host: example.com\r
\r
"""

REQUEST_EMPTY_HOST_B = """
GET http://user@tempesta-tech.com/ HTTP/1.1\r
Host: \r
\r
"""


class FrangHostRequiredTestCase(tester.TempestaTest):
    """
    Tests for non-TLS related checks in 'http_host_required' directive.

    See TLSMatchHostSni test for other cases.
    """

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

    def test_host_header_set_ok(self):
        """Test with header `host`, success."""
        self.start_all()

        deproxy_cl = self.get_client('client')
        deproxy_cl.start()
        deproxy_cl.make_requests(
            REQUEST_SUCCESS,
        )
        deproxy_cl.wait_for_response()
        self.assertEqual(
            4,
            len(deproxy_cl.responses),
        )
        self.assertFalse(
            deproxy_cl.connection_is_closed(),
        )

    def test_empty_host_header(self):
        """Test with empty header `host`."""
        self._test_base_scenario(
            request_body=REQUEST_EMPTY_HOST,
        )

    def test_host_header_missing(self):
        """Test with missing header `host`."""
        self._test_base_scenario(
            request_body='GET / HTTP/1.1\r\n\r\n',
        )

    def test_host_header_with_old_proto(self):
        """
        Test with header `host` and http v 1.0.

        Host header in http request below http/1.1. Restricted by
        Tempesta security rules.
        """
        self._test_base_scenario(
            request_body='GET / HTTP/1.0\r\nHost: tempesta-tech.com\r\n\r\n',
            expected_warning=WARN_OLD_PROTO,
        )

    def test_host_header_mismatch(self):
        """Test with mismatched header `host`."""
        self._test_base_scenario(
            request_body=REQUEST_MISMATCH,
            expected_warning=WARN_DIFFER,
        )

    def test_host_header_mismatch_empty(self):
        """
        Test with Host header is empty.

        Only authority in uri points to specific virtual host.
        Not allowed by RFC.
        """
        self._test_base_scenario(
            request_body=REQUEST_EMPTY_HOST_B,
        )

    def test_host_header_as_ip(self):
        """Test with header `host` as ip address."""
        self._test_base_scenario(
            request_body='GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n',
            expected_warning=WARN_IP_ADDR,
        )

    def test_host_header_as_ip6(self):
        """Test with header `host` as ip v6 address."""
        self._test_base_scenario(
            request_body='GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n',
            expected_warning=WARN_IP_ADDR,
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


CURL_A = '-Ikf -v --http2 https://127.0.0.4:443/ -H "Host: tempesta-tech.com"'
CURL_B = '-Ikf -v --http2 https://127.0.0.4:443/'
CURL_C = '-Ikf -v --http2 https://127.0.0.4:443/ -H "Host: "'
CURL_D = '-Ikf -v --http2 https://127.0.0.4:443/ -H "Host: example.com"'
CURL_E = '-Ikf -v --http2 https://127.0.0.4:443/ -H "Host: 127.0.0.1"'
CURL_F = '-Ikf -v --http2 https://127.0.0.4:443/ -H "Host: [::1]"'


backends = [
    {
        'id': 'nginx',
        'type': 'nginx',
        'port': '8000',
        'status_uri': 'http://${server_ip}:8000/nginx_status',
        'config': """
            pid ${pid};
            worker_processes  auto;
            events {
                worker_connections   1024;
                use epoll;
            }
            http {
                keepalive_timeout ${server_keepalive_timeout};
                keepalive_requests ${server_keepalive_requests};
                sendfile         on;
                tcp_nopush       on;
                tcp_nodelay      on;
                open_file_cache max=1000;
                open_file_cache_valid 30s;
                open_file_cache_min_uses 2;
                open_file_cache_errors off;
                error_log /dev/null emerg;
                access_log off;
                server {
                    listen        ${server_ip}:8000;
                    location / {
                        return 200;
                    }
                    location /nginx_status {
                        stub_status on;
                    }
                }
            }
        """,
    },
]

clients = [
    {
        'id': 'curl-1',
        'type': 'external',
        'binary': 'curl',
        'ssl': True,
        'cmd_args': CURL_A,
    },
    {
        'id': 'curl-2',
        'type': 'external',
        'binary': 'curl',
        'ssl': True,
        'cmd_args': CURL_B,
    },
    {
        'id': 'curl-3',
        'type': 'external',
        'binary': 'curl',
        'ssl': True,
        'cmd_args': CURL_C,
    },
    {
        'id': 'curl-4',
        'type': 'external',
        'binary': 'curl',
        'ssl': True,
        'cmd_args': CURL_D,
    },
    {
        'id': 'curl-5',
        'type': 'external',
        'binary': 'curl',
        'ssl': True,
        'cmd_args': CURL_E,
    },
    {
        'id': 'curl-6',
        'type': 'external',
        'binary': 'curl',
        'ssl': True,
        'cmd_args': CURL_F,
    },
]

tempesta = {
    'config': """
        frang_limits {
            http_host_required;
        }

        listen 127.0.0.4:443 proto=h2;

        srv_group default {
            server ${server_ip}:8000;
        }

        vhost tempesta-cat {
            proxy_pass default;
        }

        tls_match_any_server_name;
        tls_certificate RSA/tfw-root.crt;
        tls_certificate_key RSA/tfw-root.key;

        cache 0;
        cache_fulfill * *;
        block_action attack reply;

        http_chain {
            -> tempesta-cat;
        }
    """,
}


class FrangHostRequiredH2TestCase(tester.TempestaTest):
    """Tests for checks 'http_host_required' directive with http2."""

    clients = clients

    backends = backends

    tempesta = tempesta

    def setUp(self):
        """Set up test."""
        super().setUp()
        self.klog = dmesg.DmesgFinder(ratelimited=False)

    def test_h2_host_header_ok(self):
        """Test with header `host`, success."""
        curl = self.get_client('curl-1')

        self.start_all_servers()
        self.start_tempesta()

        curl.start()
        self.wait_while_busy(curl)

        self.assertEqual(
            CURL_CODE_OK,
            curl.returncode,
            ERROR_CURL.format(
                str(curl.returncode),
            ),
        )
        self.assertEqual(
            self.klog.warn_count(WARN_IP_ADDR),
            COUNT_WARNINGS_ZERO,
            ERROR_MSG,
        )
        curl.stop()

    def test_h2_empty_host_header(self):
        """
        Test with empty header `host`.

        If there is no header `host`, curl set up it with ip address.
        """
        self._test_base_scenario(
            curl_cli_id='curl-2',
            expected_warning=WARN_IP_ADDR,
        )

    def test_h2_host_header_missing(self): 
        """Test with missing header `host`."""
        self._test_base_scenario(
            curl_cli_id='curl-3',
            expected_warning=WARN_HEADER_MISSING
        )

    def test_h2_host_header_mismatch(self):
        """Test with mismatched header `host`."""
        self._test_base_scenario(
            curl_cli_id='curl-4',
            expected_warning=WARN_HEADER_MISMATCH,
            curl_code=CURL_CODE_OK,
        )

    def test_h2_host_header_as_ip(self):
        """Test with header `host` as ip address."""
        self._test_base_scenario(
            curl_cli_id='curl-5',
            expected_warning=WARN_IP_ADDR,
        )

    def test_h2_host_header_as_ipv6(self):
        """Test with header `host` as ip v6 address."""
        self._test_base_scenario(
            curl_cli_id='curl-6',
            expected_warning=WARN_HEADER_MISMATCH,
            curl_code=CURL_CODE_OK,
        )

    def _test_base_scenario(
        self,
        curl_cli_id: str,
        expected_warning: str = WARN_UNKNOWN,
        curl_code: int = CURL_CODE_BAD,
    ):
        """
        Test base scenario for process different requests.

        Args:
            curl_cli_id (str): curl client instance id
            expected_warning (str): expected warning in logs
        """
        curl_cli = self.get_client(
            curl_cli_id,
        )

        self.start_all_servers()
        self.start_tempesta()

        curl_cli.start()
        self.wait_while_busy(curl_cli)

        self.assertEqual(
            curl_code,
            curl_cli.returncode,
        )
        self.assertEqual(
            self.klog.warn_count(expected_warning),
            COUNT_WARNINGS_OK,
            ERROR_MSG,
        )
        curl_cli.stop()