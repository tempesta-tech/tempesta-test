"""
Base TestCase class for reconfiguration on-the-fly stress tests.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester
from framework.external_client import ExternalTester
from helpers.control import Tempesta


class LiveReconfStressTestCase(tester.TempestaTest):
    """Class extending Basic tempesta test class with methods
    used for testing reconfiguration on the fly.
    """

    def make_curl_request(self, curl_client_id: str) -> str:
        """
        Make `curl` request.

        Args:
            curl_client_id (str): curl client id to make request for

        Returns:
            str: server response to the request as string
        """
        client: ExternalTester = self.get_client(curl_client_id)
        client.start()
        self.wait_while_busy(client)
        self.assertEqual(
            0,
            client.returncode,
            msg=(f"Curl return code is not 0. Received - {client.returncode}."),
        )
        client.stop()
        return client.response_msg

    def reload_config(
        self,
        tempesta: Tempesta,
        start_conf_item: str,
        reloaded_conf_item: str,
    ) -> None:
        """
        Changing, reloading, and checking Tempesta reloaded configuration.

        Args:
            tempesta: object of working Tempesta
            start_conf_item: string object
            reloaded_conf_item: string object

        """
        # config Tempesta change
        tempesta.config.defconfig = tempesta.config.defconfig.replace(
            start_conf_item,
            reloaded_conf_item,
        )

        # reload Tempesta
        tempesta.reload()

        # check logs Tempesta after reload
        self._check_tfw_log()

        # check Tempesta reload config
        self.assertIn(
            reloaded_conf_item,
            tempesta.config.get_config(),
        )

    def _check_tfw_log(self) -> None:
        """Checking for errors in the Tempesta log."""
        self.oops.update()
        self.assertFalse(len(self.oops.log_findall("ERROR")))

    def _check_start_config(
        self,
        tempesta: Tempesta,
        start_conf_item: str,
        reloaded_conf_item: str,
    ) -> None:
        """
        Checking the Tempesta start configuration.

        Args:
            tempesta: object of working Tempesta
            start_conf_item: string object
            reloaded_conf_item: string object

        """
        self.assertIn(
            start_conf_item,
            tempesta.config.get_config(),
        )

        self.assertNotIn(
            reloaded_conf_item,
            tempesta.config.get_config(),
        )


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
