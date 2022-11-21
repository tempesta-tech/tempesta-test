"""Tests for Frang directive tls-related."""
import time

from t_frang.frang_test_case import FrangTestCase

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

ERROR_INCOMP_CONN = "Warning: frang: incomplete TLS connections rate exceeded"


class FrangTlsIncompleteTestCase(FrangTestCase):
    """
    Tests for 'tls_incomplete_connection_rate'.
    """

    clients = [
        {
            "id": "curl-1",
            "type": "external",
            "binary": "curl",
            "ssl": False,
            "cmd_args": '-If -v https://${tempesta_ip}:443/ -H "Host: tempesta-tech.com:8765"',
        }
    ]

    tempesta = {
        "config": """
            frang_limits {
                tls_incomplete_connection_rate 4;
                ip_block off;
            }

            listen 443 proto=https;

            server ${server_ip}:8000;

            tls_match_any_server_name;
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;

            cache 0;
            block_action attack reply;
        """,
    }

    def _base_scenario(self, steps):
        """
        Create several client connections with fail.
        If number of connections is more than 4 they will be blocked.
        """
        curl = self.get_client("curl-1")

        self.start_all_services(client=False)

        # tls_incomplete_connection_rate 4; increase to catch limit
        for step in range(steps):
            curl.run_start()
            self.wait_while_busy(curl)
            curl.stop()

            # until rate limit is reached
            if step < 4:
                self.assertFrangWarning(warning=ERROR_INCOMP_CONN, expected=0)
            else:
                # rate limit is reached
                time.sleep(1)
                self.assertFrangWarning(warning=ERROR_INCOMP_CONN, expected=1)

    def test_tls_incomplete_connection_rate(self):
        self._base_scenario(steps=5)

    def test_tls_incomplete_connection_rate_without_reaching_the_limit(self):
        self._base_scenario(steps=3)

    def test_tls_incomplete_connection_rate_on_the_limit(self):
        self._base_scenario(steps=4)
