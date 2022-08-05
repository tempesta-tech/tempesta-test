"""Tests for Frang  length related directives."""
from t_frang.frang_test_case import ONE, FrangTestCase


class FrangLengthTestCase(FrangTestCase):
    """Tests for length related directives."""

    clients = [
        {
            'id': 'curl-1',
            'type': 'external',
            'binary': 'curl',
            'cmd_args': '-Ikf -v http://127.0.0.4:8765/over_5 -H "Host: tempesta-tech.com:8765"',  # noqa:E501'
        },
        {
            'id': 'curl-2',
            'type': 'external',
            'binary': 'curl',
            'cmd_args': '-Ikf -v http://127.0.0.4:8765/ -H "Host: tempesta-tech.com:8765"  -H "X-Long: {0}"'.format(  # noqa:E501'
                'one' * 100,
            ),
        },
        {
            'id': 'curl-3',
            'type': 'external',
            'binary': 'curl',
            'cmd_args': '-kf -v http://127.0.0.4:8765/ -H "Host: tempesta-tech.com:8765" -d {0}'.format(  # noqa:E501'
                {'some_key_long_one': 'some_value'},
            ),
        },
    ]

    tempesta = {
        'config': """
            frang_limits {
                http_uri_len 5;
                http_field_len 300;
                http_body_len 10;
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

    def test_uri_len(self):
        """
        Test 'http_uri_len'.

        Set up `http_uri_len 5;` and make request with uri greater length

        """
        curl = self.get_client('curl-1')

        self.start_all_servers()
        self.start_tempesta()

        curl.start()
        self.wait_while_busy(curl)

        self.assertEqual(
            self.klog.warn_count(
                ' Warning: parsed request has been filtered out:',
            ),
            ONE,
        )
        self.assertEqual(
            self.klog.warn_count(
                'Warning: frang: HTTP URI length exceeded for',
            ),
            ONE,
        )

        curl.stop()

    def test_field_len(self):
        """
        Test 'http_field_len'.

        Set up `http_field_len 30;` and make request with header greater length

        """
        curl = self.get_client('curl-2')

        self.start_all_servers()
        self.start_tempesta()

        curl.start()
        self.wait_while_busy(curl)

        self.assertEqual(
            self.klog.warn_count(
                ' Warning: parsed request has been filtered out:',
            ),
            ONE,
        )
        self.assertEqual(
            self.klog.warn_count(
                'Warning: frang: HTTP field length exceeded for',
            ),
            ONE,
        )

        curl.stop()

    def test_body_len(self):
        """
        Test 'http_body_len'.

        Set up `http_body_len 10;` and make request with body greater length

        """
        curl = self.get_client('curl-3')

        self.start_all_servers()
        self.start_tempesta()

        curl.start()
        self.wait_while_busy(curl)

        self.assertEqual(
            self.klog.warn_count(
                ' Warning: parsed request has been filtered out:',
            ),
            ONE,
        )
        self.assertEqual(
            self.klog.warn_count(
                'Warning: frang: HTTP body length exceeded for',
            ),
            ONE,
        )

        curl.stop()
