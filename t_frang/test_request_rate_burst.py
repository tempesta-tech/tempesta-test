"""Tests for Frang directive `request_rate` and 'request_burst'."""
import time

from t_frang.frang_test_case import FrangTestCase

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

DELAY = 0.125
ERROR_MSG = 'Warning: frang: request {0} exceeded for'
ERROR_MSG_BURST = 'Warning: frang: requests burst exceeded'


class FrangRequestRateTestCase(FrangTestCase):
    """Tests for 'request_rate' directive."""

    clients = [
        {
            'id': 'curl-1',
            'type': 'external',
            'binary': 'curl',
            'cmd_args': '-Ikf -v http://127.0.0.4:8765/ -H "Host: tempesta-tech.com:8765"',
        },
    ]

    tempesta = {
        'config': """
            frang_limits {
                request_rate 4;
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

    def test_request_rate(self):
        """Test 'request_rate'."""
        curl = self.get_client('curl-1')

        self.start_all_servers()
        self.start_tempesta()

        # request_rate 4; in tempesta, increase to catch limit
        request_rate = 5

        for step in range(request_rate):
            curl.start()
            self.wait_while_busy(curl)

            # delay to split tests for `rate` and `burst`
            time.sleep(DELAY)

            curl.stop()

            # until rate limit is reached
            if step < request_rate - 1:
                self.assertEqual(
                    self.klog.warn_count(ERROR_MSG.format('rate')),
                    0,
                    self.assert_msg.format(
                        exp=0,
                        got=self.klog.warn_count(ERROR_MSG.format('rate')),
                    ),
                )

            else:
                # rate limit is reached
                self.assertEqual(
                    self.klog.warn_count(ERROR_MSG.format('rate')),
                    1,
                    self.assert_msg.format(
                        exp=1,
                        got=self.klog.warn_count(ERROR_MSG.format('rate')),
                    ),
                )

    def test_request_rate_without_reaching_the_limit(self):
        """Test 'request_rate'."""
        curl = self.get_client('curl-1')

        self.start_all_servers()
        self.start_tempesta()

        # request_rate 4; in tempesta
        request_rate = 3

        for step in range(request_rate):
            curl.start()
            self.wait_while_busy(curl)

            # delay to split tests for `rate` and `burst`
            time.sleep(DELAY)

            curl.stop()

            self.assertEqual(
                    self.klog.warn_count(ERROR_MSG.format('rate')),
                    0,
                    self.assert_msg.format(
                        exp=0,
                        got=self.klog.warn_count(ERROR_MSG.format('rate')),
                    ),
                )

    def test_request_rate_on_the_limit(self):
        """Test 'request_rate'."""
        curl = self.get_client('curl-1')

        self.start_all_servers()
        self.start_tempesta()

        # request_rate 4; in tempesta
        request_rate = 4

        for step in range(request_rate):
            curl.start()
            self.wait_while_busy(curl)

            # delay to split tests for `rate` and `burst`
            time.sleep(DELAY)

            curl.stop()

            self.assertEqual(
                    self.klog.warn_count(ERROR_MSG.format('rate')),
                    0,
                    self.assert_msg.format(
                        exp=0,
                        got=self.klog.warn_count(ERROR_MSG.format('rate')),
                    ),
                )


class FrangRequestBurstTestCase(FrangTestCase):
    """Tests for and 'request_burst' directive."""

    clients = [
        {
            'id': 'curl-1',
            'type': 'external',
            'binary': 'curl',
            'cmd_args': '-Ikf -v http://127.0.0.4:8765/ -H "Host: tempesta-tech.com:8765"',
        },
    ]
    tempesta = {
        'config': """
            frang_limits {
                request_burst 3;
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

    def test_request_burst_reached(self):
        """Test 'request_burst' is reached.
        Sometimes the test fails because the curl takes a long time to run and it affects more than 125ms
        this means that in 125 ms there will be less than 4 requests and the test will not reach the limit
        """
        curl = self.get_client('curl-1')
        self.start_all_servers()
        self.start_tempesta()

        # request_burst 3; in tempesta, increase to catch limit
        request_burst = 4

        for _ in range(request_burst):
            curl.start()
            self.wait_while_busy(curl)
            curl.stop()

        self.assertEqual(
            self.klog.warn_count(ERROR_MSG_BURST),
            1,
            self.assert_msg.format(
                exp=1,
                got=self.klog.warn_count(ERROR_MSG_BURST),
            ),
        )

    def test_request_burst_not_reached_timeout(self):
        """Test 'request_burst' is NOT reached."""
        curl = self.get_client('curl-1')
        self.start_all_servers()
        self.start_tempesta()

        # request_burst 3; in tempesta,
        request_burst = 5

        for _ in range(request_burst):
            time.sleep(0.125)  # the limit works only on an interval of 125 ms
            curl.start()
            self.wait_while_busy(curl)
            curl.stop()

        self.assertEqual(
            self.klog.warn_count(ERROR_MSG_BURST),
            0,
            self.assert_msg.format(
                exp=0,
                got=self.klog.warn_count(ERROR_MSG_BURST),
            ),
        )

    def test_request_burst_on_the_limit(self):
        # Sometimes the test fails because the curl takes a long time to run and it affects more than 125ms
        curl = self.get_client('curl-1')
        self.start_all_servers()
        self.start_tempesta()

        # request_burst 3; in tempesta,
        request_burst = 3

        for _ in range(request_burst):
            curl.start()
            self.wait_while_busy(curl)
            curl.stop()

        self.assertEqual(
            self.klog.warn_count(ERROR_MSG_BURST),
            0,
            self.assert_msg.format(
                exp=0,
                got=self.klog.warn_count(ERROR_MSG_BURST),
            ),
        )


class FrangRequestRateBurstTestCase(FrangTestCase):
    """Tests for 'request_rate' and 'request_burst' directive."""

    clients = [
        {
            'id': 'curl-1',
            'type': 'external',
            'binary': 'curl',
            'cmd_args': '-Ikf -v http://127.0.0.4:8765/ -H "Host: tempesta-tech.com:8765"',
        },
    ]

    tempesta = {
        'config': """
            frang_limits {
                request_rate 4;
                request_burst 3;
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

    def test_request_rate_reached(self):
        """Test 'request_rate'."""
        curl = self.get_client('curl-1')

        self.start_all_servers()
        self.start_tempesta()

        # request_rate 4; in tempesta, increase to catch limit
        request_rate = 5

        for step in range(request_rate):
            curl.start()
            self.wait_while_busy(curl)

            # delay to split tests for `rate` and `burst`
            time.sleep(DELAY)

            curl.stop()

            # until rate limit is reached
            if step < request_rate - 1:
                self.assertEqual(
                    self.klog.warn_count(ERROR_MSG.format('rate')),
                    0,
                    self.assert_msg.format(
                        exp=0,
                        got=self.klog.warn_count(ERROR_MSG.format('rate')),
                    ),
                )

            else:
                # rate limit is reached
                self.assertEqual(
                    self.klog.warn_count(ERROR_MSG.format('rate')),
                    1,
                    self.assert_msg.format(
                        exp=1,
                        got=self.klog.warn_count(ERROR_MSG.format('rate')),
                    ),
                )
                self.assertEqual(
                    self.klog.warn_count(ERROR_MSG_BURST),
                    0,
                    self.assert_msg.format(
                        exp=0,
                        got=self.klog.warn_count(ERROR_MSG_BURST),
                    ),
                )

    def test_request_rate_without_reaching_the_limit(self):
        """Test 'request_rate'."""
        curl = self.get_client('curl-1')

        self.start_all_servers()
        self.start_tempesta()

        # request_rate 4; in tempesta
        request_rate = 3

        for step in range(request_rate):
            curl.start()
            self.wait_while_busy(curl)

            # delay to split tests for `rate` and `burst`
            time.sleep(DELAY)

            curl.stop()

            self.assertEqual(
                    self.klog.warn_count(ERROR_MSG.format('rate')),
                    0,
                    self.assert_msg.format(
                        exp=0,
                        got=self.klog.warn_count(ERROR_MSG.format('rate')),
                    ),
                )
            self.assertEqual(
                    self.klog.warn_count(ERROR_MSG_BURST),
                    0,
                    self.assert_msg.format(
                        exp=0,
                        got=self.klog.warn_count(ERROR_MSG_BURST),
                    ),
                )

    def test_request_rate_on_the_limit(self):
        """Test 'request_rate'."""
        curl = self.get_client('curl-1')

        self.start_all_servers()
        self.start_tempesta()

        # request_rate 4; in tempesta
        request_rate = 4

        for step in range(request_rate):
            curl.start()
            self.wait_while_busy(curl)

            # delay to split tests for `rate` and `burst`
            time.sleep(DELAY)

            curl.stop()

            self.assertEqual(
                    self.klog.warn_count(ERROR_MSG.format('rate')),
                    0,
                    self.assert_msg.format(
                        exp=0,
                        got=self.klog.warn_count(ERROR_MSG.format('rate')),
                    ),
                )
            self.assertEqual(
                    self.klog.warn_count(ERROR_MSG_BURST),
                    0,
                    self.assert_msg.format(
                        exp=0,
                        got=self.klog.warn_count(ERROR_MSG_BURST),
                    ),
                )

    def test_request_burst_reached(self):
        """Test 'request_burst' is reached.
        Sometimes the test fails because the curl takes a long time to run and it affects more than 125ms
        this means that in 125 ms there will be less than 4 requests and the test will not reach the limit
        """
        curl = self.get_client('curl-1')
        self.start_all_servers()
        self.start_tempesta()

        # request_burst 3; in tempesta, increase to catch limit
        request_burst = 4

        for _ in range(request_burst):
            curl.start()
            self.wait_while_busy(curl)
            curl.stop()

        self.assertEqual(
            self.klog.warn_count(ERROR_MSG_BURST),
            1,
            self.assert_msg.format(
                exp=1,
                got=self.klog.warn_count(ERROR_MSG_BURST),
            ),
        )
        self.assertEqual(
            self.klog.warn_count(ERROR_MSG.format('rate')),
            0,
            self.assert_msg.format(
                exp=0,
                got=self.klog.warn_count(ERROR_MSG.format('rate')),
            ),
        )

    def test_request_burst_not_reached_timeout(self):
        """Test 'request_burst' is NOT reached."""
        curl = self.get_client('curl-1')
        self.start_all_servers()
        self.start_tempesta()

        # request_burst 3; in tempesta,
        request_burst = 5

        for _ in range(request_burst):
            time.sleep(DELAY*2)  # the limit works only on an interval of 125 ms
            curl.start()
            self.wait_while_busy(curl)
            curl.stop()

        self.assertEqual(
            self.klog.warn_count(ERROR_MSG_BURST),
            0,
            self.assert_msg.format(
                exp=0,
                got=self.klog.warn_count(ERROR_MSG_BURST),
            ),
        )
        self.assertEqual(
            self.klog.warn_count(ERROR_MSG.format('rate')),
            0,
            self.assert_msg.format(
                exp=0,
                got=self.klog.warn_count(ERROR_MSG.format('rate')),
            ),
        )

    def test_request_burst_on_the_limit(self):
        # Sometimes the test fails because the curl takes a long time to run and it affects more than 125ms
        curl = self.get_client('curl-1')
        self.start_all_servers()
        self.start_tempesta()

        # request_burst 3; in tempesta,
        request_burst = 3

        for _ in range(request_burst):
            curl.start()
            self.wait_while_busy(curl)
            curl.stop()

        self.assertEqual(
            self.klog.warn_count(ERROR_MSG_BURST),
            0,
            self.assert_msg.format(
                exp=0,
                got=self.klog.warn_count(ERROR_MSG_BURST),
            ),
        )
        self.assertEqual(
            self.klog.warn_count(ERROR_MSG.format('rate')),
            0,
            self.assert_msg.format(
                exp=0,
                got=self.klog.warn_count(ERROR_MSG.format('rate')),
            ),
        )
