"""Tests for Frang directive `ip_block`."""
from t_frang.frang_test_case import ONE, ZERO, FrangTestCase

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class FrangIpBlockTestCase(FrangTestCase):
    """Tests for 'ip_block' directive."""

    clients = [
        {
            'id': 'curl-1',
            'type': 'external',
            'binary': 'curl',
            'cmd_args': '-Ikf -v http://127.0.0.4:8765/',
        },
    ]

    tempesta = {
        'config': """
            frang_limits {
                ip_block on;
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

    def test_ip_block(self):
        """
        Test 'ip_block'.

        Curl sent request with header Host as ip (did not set up another).
        It is reason for violation and trigger this limit.
        """
        curl = self.get_client('curl-1')

        self.start_all_servers()
        self.start_tempesta()

        curl.start()
        self.wait_while_busy(curl)

        self.assertEqual(
            curl.returncode,
            ZERO,
        )

        self.assertEqual(
            self.klog.warn_count(
                'Warning: block client:',
            ),
            ONE,
        )
        self.assertEqual(
            self.klog.warn_count(
                'frang: Host header field contains IP address',
            ),
            ONE,
        )

        curl.stop()
