"""
TestCase for multiple listening sockets.

Config for test is being auto generated and imported before test.
"""
from framework import tester
from multiple_listeners.config_generator import ConfigAutoGenerator
import importlib


config_auto_generator = ConfigAutoGenerator()
config_auto_generator.generate()
test_config = importlib.import_module('multiple_listeners.config_for_tests')

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

ID = 'id'
CONNECTION_TIMEOUT = 2
STATUS_OK = '200'
H2SPEC_OK = '4 passed'
H2SPEC_EXTRA_SETTINGS = 'generic/4'


class TestMultipleListening(tester.TempestaTest):

    backends = test_config.backends
    clients = test_config.clients
    tempesta = test_config.tempesta

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()

    def test_multiple_listeners_success(self):

        # h2spec
        for cli in test_config.clients:
            if cli[ID].startswith('h2spec'):
                h2spec = self.get_client(
                    cli[ID],
                )
                h2spec.options.append(H2SPEC_EXTRA_SETTINGS)

        self.start_all()

        for cli in test_config.clients:

            # h2spec
            if cli[ID].startswith('h2spec'):
                h2spec = self.get_client(
                    cli[ID],
                )
                self.wait_while_busy(h2spec)
                response_h2spec = h2spec.resq.get(True, 1)[0].decode()
                self.assertIn(
                    H2SPEC_OK,
                    response_h2spec,
                )

            # curl
            if cli[ID].startswith('curl'):
                curl = self.get_client(
                    cli[ID],
                )
                curl.start()
                self.wait_while_busy(curl)
                response = curl.resq.get(True, 1)[0].decode()
                self.assertIn(
                    STATUS_OK,
                    response,
                )
                curl.stop()
