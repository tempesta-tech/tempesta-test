"""TestCase for change Tempesta config on the fly."""
from framework import tester
from multiple_listeners import config_for_tests_on_fly as tc


__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

WRK_SCRIPT = 'conn_close'  # with header 'connection: close'
STATUS_OK = 200

SOCKET_START = ('127.0.0.4:8282', )
SOCKET_AFTER_RELOAD = ('127.0.1.5:7654', )


def make_tempesta_config(sockets: tuple) -> dict:
    """
    Add `listen` socket to Tempesta config.

    Args:
        sockets (tuple): sockets to add

    Returns:
        config (dict): Tempesta config

    """
    listen_parameters = ''
    for soc in sockets:
        listen_parameters += 'listen {0};\n\t'.format(soc)
    return {
        'config': tc.tempesta['config'] % listen_parameters,
    }


def make_test_clients() -> list:
    """
    Create wrk clients.

    Returns:
        clients (list): created clients

    """
    test_clients = []
    for soc in (SOCKET_START + SOCKET_AFTER_RELOAD):
        test_clients.append(
            {
                'id': 'wrk-{0}'.format(soc),
                'type': 'wrk',
                'addr': soc,
            }
        )
        test_clients.append(
            {
                'id': 'curl-{0}'.format(soc),
                'type': 'external',
                'binary': 'curl',
                'cmd_args': '-Ikf http://{0}/'.format(soc),
            }
        )
    return test_clients


class TestOnTheFly(tester.TempestaTest):

    backends = tc.backends
    clients = make_test_clients()
    tempesta = make_tempesta_config(SOCKET_START)

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()

    def test_change_config_on_the_fly(self):
        """
        Test Tempesta for change config on the fly.

        Start Tempesta with one config - start wrk -
            - reload Tempesta with new config -
            - start new wrk
        """

        self.start_all()

        tempesta = self.get_tempesta()

        for soc_start in SOCKET_START:
            wrk = self.get_client('wrk-{0}'.format(soc_start))
            wrk.set_script(WRK_SCRIPT)
            wrk.start()
            # TODO self.wait_while_busy(wrk)

            self.assertIn(
                'listen {0};'.format(soc_start),
                tempesta.config.get_config(),
            )

        # check reload sockets not in config
        for soc_reload in SOCKET_AFTER_RELOAD:
            self.assertRaises(
                Exception,
                self.make_curl_request,
                'curl-{0}'.format(soc_reload)
            )
            self.assertNotIn(
                'listen {0};'.format(soc_reload),
                tempesta.config.get_config(),
            )

        # change config and reload Tempesta
        tempesta.config.defconfig = make_tempesta_config(
            SOCKET_AFTER_RELOAD,
        )['config']
        tempesta.reload()

        # check old sockets  not in config
        for soc_start in SOCKET_START:
            self.assertRaises(
                Exception,
                self.make_curl_request,
                'curl-{0}'.format(soc_start)
            )
            self.assertNotIn(
                'listen {0};'.format(soc_start),
                tempesta.config.get_config(),
            )

        for soc_reload in SOCKET_AFTER_RELOAD:
            wrk_after = self.get_client('wrk-{0}'.format(soc_reload))
            wrk_after.set_script(WRK_SCRIPT)
            wrk_after.start()
            self.wait_while_busy(wrk_after)
            wrk_after.stop()
            self.assertIn(
                STATUS_OK,
                wrk_after.statuses,
            )
            self.assertGreater(
                wrk_after.statuses[STATUS_OK],
                0,
            )

            self.assertIn(
                'listen {0};'.format(soc_reload),
                tempesta.config.get_config(),
            )

    def make_curl_request(self, curl_client_id: str):
        """
        Make `curl` request.

        Args:
            curl_client_id (str): curl client id to make request for

        """
        curl = self.get_client(curl_client_id)
        curl.start()
        self.wait_while_busy(curl)
        response = curl.resq.get(True, 1)[0].decode()
        self.assertIn(
            STATUS_OK,
            response,
        )
        curl.stop()
