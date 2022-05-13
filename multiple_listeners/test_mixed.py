"""TestCase for mixed listening sockets."""
from framework import tester
from multiple_listenings import config_for_tests_mixed as tc


__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

STATUS_OK = '200'


class TestMixedListeners(tester.TempestaTest):

    backends = tc.backends
    clients = tc.clients
    tempesta = tc.tempesta

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()

    def test_mixed_h2_success(self):
        """
        Test h2 success situation.

        One `true` client apply h2 client for h2 socket,
        second `false` client apply h2 client for https socket,
        """

        self.start_all()

        curl_h2_true = self.get_client('curl-h2-true')
        curl_h2_true.start()
        self.wait_while_busy(curl_h2_true)
        response = curl_h2_true.resq.get(True, 1)[0].decode()
        self.assertIn(
            STATUS_OK,
            response,
        )
        curl_h2_true.stop()

        curl_h2_false = self.get_client('curl-h2-false')
        curl_h2_false.start()
        self.wait_while_busy(curl_h2_false)
        response = curl_h2_false.resq.get(True, 1)[0].decode()
        self.assertNotIn(
            STATUS_OK,
            response,
        )
        curl_h2_false.stop()

    def test_mixed_https_success(self):
        """
        Test h2 success situation.

        One `true` client apply h2 client for h2 socket,
        second `false` client apply h2 client for https socket,
        """

        self.start_all()

        curl_https_true = self.get_client('curl-https-true')
        curl_https_true.start()
        self.wait_while_busy(curl_https_true)
        response = curl_https_true.resq.get(True, 1)[0].decode()
        self.assertIn(
            STATUS_OK,
            response,
        )
        curl_https_true.stop()

        curl_https_false = self.get_client('curl-https-false')
        curl_https_false.start()
        self.wait_while_busy(curl_https_false)
        response = curl_https_false.resq.get(True, 1)[0].decode()
        self.assertNotIn(
            STATUS_OK,
            response,
        )
        curl_https_false.stop()
