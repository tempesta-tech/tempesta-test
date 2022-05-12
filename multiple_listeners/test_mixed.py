from framework import tester
from multiple_listenings import config_for_tests_mixed as tc


__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

CONNECTION_TIMEOUT = 2
STATUS_OK = '200'
H2SPEC_OK = '4 passed'
H2SPEC_EXTRA_SETTINGS = 'generic/4'


class TestLoad(tester.TempestaTest):

    backends = tc.backends
    clients = tc.clients
    tempesta = tc.tempesta

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()

    def test_mixed_success(self):

        # h2spec
        for cli in tc.clients:
            if cli['id'].startswith('h2spec'):
                h2spec = self.get_client(
                    cli['id'],
                )
                h2spec.options.append(H2SPEC_EXTRA_SETTINGS)

        self.start_all()

        for cli in tc.clients:

            # h2spec
            if cli['id'].startswith('h2spec'):
                h2spec = self.get_client(
                    cli['id'],
                )
                self.wait_while_busy(h2spec)
                response_h2spec = h2spec.resq.get(True, 1)[0].decode()
                self.assertIn(
                    H2SPEC_OK,
                    response_h2spec,
                )

            # curl
            if cli['id'].startswith('curl'):
                curl = self.get_client(
                    cli['id'],
                )
                curl.start()
                self.wait_while_busy(curl)
                response = curl.resq
                self.assertIn(
                    STATUS_OK,
                    response,
                )
                curl.stop()
