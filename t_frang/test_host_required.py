"""Tests for Frang directive `http_host_required`."""
from framework import tester
from helpers import dmesg

from t_frang import config_for_tests_host_required as test_conf


CURL_CODE_OK = 0
CURL_CODE_BAD = 1
COUNT_WARNINGS_OK = 1
COUNT_WARNINGS_ZERO = 0


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
            'response_content': test_conf.RESPONSE_CONTENT,
        },
    ]

    tempesta = {
        'config': test_conf.TEMPESTA_CONF,
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
            test_conf.REQUEST_SUCCESS,
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
            request_body=test_conf.REQUEST_EMPTY_HOST,
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
            expected_warning=test_conf.WARN_OLD_PROTO,
        )

    def test_host_header_mismatch(self):
        """Test with mismatched header `host`."""
        self._test_base_scenario(
            request_body=test_conf.REQUEST_MISMATCH,
            expected_warning=test_conf.WARN_DIFFER,
        )

    def test_host_header_mismatch_empty(self):
        """
        Test with Host header is empty.

        Only authority in uri points to specific virtual host.
        Not allowed by RFC.
        """
        self._test_base_scenario(
            request_body=test_conf.REQUEST_EMPTY_HOST_B,
        )

    def test_host_header_as_ip(self):
        """Test with header `host` as ip address."""
        self._test_base_scenario(
            request_body='GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n',
            expected_warning=test_conf.WARN_IP_ADDR,
        )

    def test_host_header_as_ip6(self):
        """Test with header `host` as ip v6 address."""
        self._test_base_scenario(
            request_body='GET / HTTP/1.1\r\nHost: [::1]:80\r\n\r\n',
            expected_warning=test_conf.WARN_IP_ADDR,
        )

    def _test_base_scenario(
        self,
        request_body: str,
        expected_warning: str = test_conf.WARN_UNKNOWN,
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
            test_conf.ERROR_MSG,
        )


class FrangHostRequiredH2TestCase(tester.TempestaTest):
    """Tests for checks 'http_host_required' directive with http2."""

    clients = test_conf.clients

    backends = test_conf.backends

    tempesta = test_conf.tempesta

    def setUp(self):
        """Set up test."""
        super().setUp()
        self.klog = dmesg.DmesgFinder(ratelimited=False)

    def test_h2_host_header_ok(self):
        """Test with header `host`, success."""
        curl = self.get_client('curl-1')

        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()

        curl.start()
        self.wait_while_busy(curl)

        self.assertEqual(
            CURL_CODE_OK,
            curl.returncode,
            test_conf.ERROR_CURL.format(
                str(curl.returncode),
            ),
        )
        self.assertEqual(
            self.klog.warn_count(test_conf.WARN_IP_ADDR),
            COUNT_WARNINGS_ZERO,
            test_conf.ERROR_MSG,
        )
        curl.stop()

    def test_h2_empty_host_header(self):
        """
        Test with empty header `host`.

        If there is no header `host`, curl set up it with ip address.
        """
        self._test_base_scenario(
            curl_cli_id='curl-2',
            expected_warning=test_conf.WARN_IP_ADDR,
        )

    def test_h2_host_header_missing(self):  # TODO no warning in logs
        """Test with missing header `host`."""
        self._test_base_scenario(
            curl_cli_id='curl-3',
        )

    def test_h2_host_header_mismatch(self):  # TODO return 200
        """Test with mismatched header `host`."""
        self._test_base_scenario(
            curl_cli_id='curl-4',
            expected_warning=test_conf.WARN_DIFFER,
        )

    def test_h2_host_header_as_ip(self):
        """Test with header `host` as ip address."""
        self._test_base_scenario(
            curl_cli_id='curl-5',
            expected_warning=test_conf.WARN_IP_ADDR,
        )

    def test_h2_host_header_as_ipv6(self):  # TODO return 200
        """Test with header `host` as ip v6 address."""
        self._test_base_scenario(
            curl_cli_id='curl-6',
            expected_warning=test_conf.WARN_IP_ADDR,
        )

    def _test_base_scenario(
        self,
        curl_cli_id: str,
        expected_warning: str = test_conf.WARN_UNKNOWN,
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
        self.deproxy_manager.start()

        curl_cli.start()
        self.wait_while_busy(curl_cli)

        self.assertEqual(
            CURL_CODE_BAD,
            curl_cli.returncode,
        )
        self.assertEqual(
            self.klog.warn_count(expected_warning),
            COUNT_WARNINGS_OK,
            test_conf.ERROR_MSG,
        )
        curl_cli.stop()
