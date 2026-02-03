"""Tests for Frang directive tls-related."""

import time

from framework.test_suite import marks
from tests.frang.frang_test_case import FrangTestCase

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
            "type": "curl",
            "addr": "${tempesta_ip}:443",
            "ssl": False,
            "headers": {
                "Host": "tempesta-tech.com:443",
            },
        }
    ]

    tempesta = {
        "config": """
            frang_limits {
                tls_incomplete_connection_rate 4;
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

    @marks.Parameterize.expand(
        [
            marks.Param(name="rate", steps=5),
            marks.Param(name="without_reaching_the_limit", steps=3),
            marks.Param(name="rate_on_the_limit", steps=4),
        ]
    )
    def test_tls_incomplete_connection(self, name, steps):
        """
        Create several client connections with fail.
        If number of connections is more than 4 they will be blocked.
        """
        curl = self.get_client("curl-1")
        curl.uri += f"[1-{steps}]"
        curl.parallel = steps
        curl.uri = curl.uri.replace("http", "https")

        self.start_all_services(client=False)

        curl.start()
        self.wait_while_busy(curl)
        curl.stop()

        time.sleep(self.timeout)

        # until rate limit is reached
        if steps <= 4:
            self.assertFrangWarning(warning=ERROR_INCOMP_CONN, expected=0)
        else:
            # rate limit is reached
            self.assertFrangWarning(warning=ERROR_INCOMP_CONN, expected=1)
