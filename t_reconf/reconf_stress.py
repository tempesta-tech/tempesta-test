"""
Base TestCase class for reconfiguration on-the-fly stress tests.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester
from framework.curl_client import CurlResponse
from run_config import CONCURRENT_CONNECTIONS, DURATION, REQUESTS_COUNT, THREADS


class LiveReconfStressTestBase(tester.TempestaTest, base=True):
    """Class extending Basic tempesta test class with methods
    used for testing reconfiguration on the fly.
    """

    clients = [
        {
            "id": "curl",
            "type": "curl",
            "http2": True,
            "addr": "${tempesta_ip}:443",
        },
        {
            "id": "h2load",
            "type": "external",
            "binary": "h2load",
            "ssl": True,
            "cmd_args": (
                " https://${tempesta_ip}:443/"
                f" --clients {CONCURRENT_CONNECTIONS}"
                f" --threads {THREADS}"
                f" --max-concurrent-streams {REQUESTS_COUNT}"
                f" --duration {DURATION}"
            ),
        },
    ]

    def make_curl_request(self, curl_client_id: str) -> str:
        """
        Make `curl` request.

        Args:
            curl_client_id (str): curl client id to make request for

        Returns:
            str: server response to the request as string
        """
        client = self.get_client(curl_client_id)
        client.start()
        self.wait_while_busy(client)
        self.assertEqual(
            0,
            client.returncode,
            msg=(f"Curl return code is not 0. Received - {client.returncode}."),
        )
        client.stop()
        return client.response_msg

    def make_curl_client_request(
        self,
        curl_client_id: str,
        headers: dict[str, str] = None,
    ) -> CurlResponse | None:
        """
        Make `curl` request.

        Args:
            curl_client_id (str): Curl client id to make request for.
            headers: A dict mapping keys to the corresponding query header values.
                Defaults to None.

        Returns:
            The object of the CurlResponse class - parsed cURL response or None.
        """
        curl = self.get_client(curl_client_id)

        if headers is None:
            headers = {}

        if headers:
            for key, val in headers.items():
                curl.headers[key] = val

        curl.start()
        self.wait_while_busy(curl)
        self.assertEqual(
            0,
            curl.returncode,
            msg=(f"Curl return code is not 0. Received - {curl.returncode}."),
        )
        curl.stop()
        return curl.last_response

    def reload_tfw_config(
        self,
        start_conf_item: str,
        reloaded_conf_item: str,
    ) -> None:
        """
        Changing, reloading, and checking Tempesta reloaded configuration.

        Args:
            start_conf_item: string object
            reloaded_conf_item: string object

        """
        tempesta = self.get_tempesta()
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

    def _check_start_tfw_config(
        self,
        start_conf_item: str,
        reloaded_conf_item: str,
    ) -> None:
        """
        Checking the Tempesta start configuration.

        Args:
            start_conf_item: String object.
            reloaded_conf_item: String object.

        """
        tempesta = self.get_tempesta()

        self.assertIn(
            start_conf_item,
            tempesta.config.get_config(),
        )

        self.assertNotIn(
            reloaded_conf_item,
            tempesta.config.get_config(),
        )


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
