"""Tests for Frang directive tls-related."""
from t_frang.frang_test_case import ONE, ZERO, FrangTestCase
import time

ERROR_TLS = 'Warning: frang: new TLS connections {0} exceeded for'
ERROR_INCOMP_CONN = 'Warning: frang: incomplete TLS connections rate exceeded'

class FrangTlsRateTestCase(FrangTestCase):
    """Tests for 'tls_connection_rate'."""

    clients = [
        {
            'id': 'curl-1',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf -v https://127.0.0.4:8765/ -H "Host: tempesta-tech.com:8765"',  # noqa:E501
        },
    ]

    tempesta = {
        'config': """
            frang_limits {
                tls_connection_rate 4;
            }

            listen 127.0.0.4:8765 proto=https;

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

    def test_tls_connection_rate(self):
        """Test 'tls_connection_rate'."""
        curl = self.get_client('curl-1')

        self.start_all_servers()
        self.start_tempesta()

        # tls_connection_rate 4; in tempesta, increase to catch limit
        request_rate = 5

        for step in range(request_rate):
            curl.start()
            self.wait_while_busy(curl)

            curl.stop()

            # until rate limit is reached
            if step < request_rate - 1:
                self.assertEqual(
                    self.klog.warn_count(ERROR_TLS.format('rate')),
                    ZERO,
                    self.assert_msg.format(
                        exp=ZERO,
                        got=self.klog.warn_count(ERROR_TLS.format('rate')),
                    ),
                )
            else:
                # rate limit is reached
                self.assertEqual(
                    self.klog.warn_count(ERROR_TLS.format('rate')),
                    ONE,
                    self.assert_msg.format(
                        exp=ONE,
                        got=self.klog.warn_count(ERROR_TLS.format('rate')),
                    ),
                )


class FrangTlsBurstTestCase(FrangTestCase):
    """Tests for 'tls_connection_burst'."""

    clients = [
        {
            'id': 'curl-1',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf -v https://127.0.0.4:8765/ -H "Host: tempesta-tech.com:8765"',  # noqa:E501
        },
    ]

    tempesta = {
        'config': """
            frang_limits {
                tls_connection_burst 4;
            }

            listen 127.0.0.4:8765 proto=https;

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

    def test_tls_connection_burst(self):
        """Test 'tls_connection_burst'."""
        curl = self.get_client('curl-1')

        self.start_all_servers()
        self.start_tempesta()

        # tls_connection_burst 4; in tempesta, increase to catch limit
        request_burst = 5

        for step in range(request_burst):
            curl.start()
            self.wait_while_busy(curl)

            curl.stop()

            # until rate limit is reached
            if step < request_burst - 1:
                self.assertEqual(
                    self.klog.warn_count(ERROR_TLS.format('burst')),
                    ZERO,
                    self.assert_msg.format(
                        exp=ZERO,
                        got=self.klog.warn_count(ERROR_TLS.format('burst')),
                    ),
                )
            else:
                # rate limit is reached
                self.assertEqual(
                    self.klog.warn_count(ERROR_TLS.format('burst')),
                    ONE,
                    self.assert_msg.format(
                        exp=ONE,
                        got=self.klog.warn_count(ERROR_TLS.format('burst')),
                    ),
                )


class FrangTlsIncompleteTestCase(FrangTestCase):
    """
    Tests for 'tls_incomplete_connection_rate'.

    """

    clients = [
        {
            'id': 'curl-1',
            'type': 'external',
            'binary': 'curl',
            'tls': False,
            'cmd_args': '-If -v https://127.0.0.4:8765/ -H "Host: tempesta-tech.com:8765"',  # noqa:E501
        },
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '8765',
            'interface' : True,
            'rps': 6
        }
    ]
#tls_match_any_server_name;
    tempesta = {
        'config': """
            frang_limits {
                tls_incomplete_connection_rate 2;
            }

            listen 127.0.0.4:8765 proto=https;

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

    def test_tls_incomplete_connection_rate(self):
        """Test 'tls_incomplete_connection_rate'."""
        curl = self.get_client('curl-1')

        self.start_all_servers()    
        self.start_tempesta()

        # tls_incomplete_connection_rate 2; increase to catch limit
        request_inc = 3

        for step in range(request_inc):
            print(f'step: {step}')
            curl.run_start()
            self.wait_while_busy(curl)
            curl.stop()

            # until rate limit is reached
            if step < request_inc - 1:
                self.assertEqual(
                    self.klog.warn_count(ERROR_INCOMP_CONN),
                    ZERO,
                    self.assert_msg.format(
                        exp=ZERO,
                        got=self.klog.warn_count(ERROR_INCOMP_CONN),
                    ),
                )
            else:
                # rate limit is reached
                time.sleep(1)
                self.assertEqual(
                    self.klog.warn_count(ERROR_INCOMP_CONN),
                    ONE,
                    self.assert_msg.format(
                        exp=ONE,
                        got=self.klog.warn_count(ERROR_INCOMP_CONN),
                    ),
                )
