"""Tests for Frang directive `http_header_cnt`."""
from t_frang.frang_test_case import ONE, FrangTestCase


class FrangHttpHeaderCountTestCase(FrangTestCase):
    """Tests for 'http_header_cnt' directive."""

    clients = [
        {
            'id': 'curl-1',
            'type': 'external',
            'binary': 'curl',
            'cmd_args': '-Ikf -v http://127.0.0.4:8765/ -H "Host: tempesta-tech.com:8765"' + ' -H "Connection: keep-alive"',  # noqa:E501
        },
    ]

    tempesta = {
        'config': """
            frang_limits {
                http_header_cnt 1;
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

    def test_client_header_timeout(self):
        """
        Test 'client_header_timeout'.

        We set up for Tempesta `http_header_cnt 1` and
        made request with 2 (two) headers
        """
        curl = self.get_client('curl-1')

        self.start_all_servers()
        self.start_tempesta()

        curl.start()
        self.wait_while_busy(curl)

        self.assertEqual(
            self.klog.warn_count(
                'Warning: frang: HTTP headers number exceeded for',
            ),
            ONE,
            'Expected msg in `journalctl`',
        )
        self.assertEqual(
            self.klog.warn_count(
                'Warning: parsed request has been filtered out',
            ),
            ONE,
            'Expected msg in `journalctl`',
        )

        curl.stop()
