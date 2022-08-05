"""Tests for Frang directive `connection_rate` and 'connection_burst'."""
import time

from t_frang.frang_test_case import DELAY, ONE, ZERO, FrangTestCase

ERROR_RATE = 'Warning: frang: new connections rate exceeded for'


class FrangConnectionRateTestCase(FrangTestCase):
    """Tests for 'request_rate' and 'request_burst' directive."""

    clients = [
        {
            'id': 'curl-1',
            'type': 'external',
            'binary': 'curl',
            'cmd_args': '-Ikf -v http://127.0.0.4:8765/ -H "Host: tempesta-tech.com:8765" -H "Connection: close"',  # noqa:E501
        },
    ]

    tempesta = {
        'config': """
            frang_limits {
                connection_rate 4;
                connection_burst 2;
            }

            listen 127.0.0.4:8765;

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

    def test_connection_rate(self):
        """Test 'connection_rate'."""
        curl = self.get_client('curl-1')

        self.start_all_servers()
        self.start_tempesta()

        # connection_rate 4 in Tempesta config increase to get limit
        connection_rate = 5

        for step in range(connection_rate):
            curl.start()
            self.wait_while_busy(curl)

            # delay to split tests for `rate` and `burst`
            time.sleep(DELAY)

            curl.stop()

            # until rate limit is reached
            if step < connection_rate - 1:
                self.assertEqual(
                    self.klog.warn_count(ERROR_RATE),
                    ZERO,
                    self.assert_msg.format(
                        exp=ZERO,
                        got=self.klog.warn_count(ERROR_RATE),
                    ),
                )

        self.assertGreater(
            self.klog.warn_count(ERROR_RATE),
            ONE,
            self.assert_msg.format(
                exp='more than {0}'.format(ONE),
                got=self.klog.warn_count(ERROR_RATE),
            ),
        )

    def test_connection_burst(self):  # TODO
        """Test 'connection_burst'."""
        curl = self.get_client('curl-1')

        self.start_all_servers()
        self.start_tempesta()

        # connection_burst 2 in Tempesta config increase to get limit
        connection_burst = 3

        for step in range(connection_burst):
            curl.start()
            self.wait_while_busy(curl)
            curl.stop()

            # until rate limit is reached
            if step < connection_burst - 1:
                self.assertEqual(
                    self.klog.warn_count(ERROR_RATE),
                    ZERO,
                    self.assert_msg.format(
                        exp=ZERO,
                        got=self.klog.warn_count(ERROR_RATE),
                    ),
                )

        self.assertEqual(
            self.klog.warn_count(ERROR_RATE),
            ONE,
            self.assert_msg.format(
                exp=ONE,
                got=self.klog.warn_count(ERROR_RATE),
            ),
        )
