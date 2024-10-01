"""
Test TempestaFW reeboot under load.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import time

from framework.parameterize import parameterize_class
from helpers import remote, tf_cfg
from run_config import CONCURRENT_CONNECTIONS, DURATION, REQUESTS_COUNT, THREADS
from test_suite import tester

STATUS_OK = "200"

TEMPESTA_NO_CACHE = {
    "config": """
        listen ${tempesta_ip}:443 proto=h2;

        server ${server_ip}:8000;
        
        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;
        max_concurrent_streams 10000;
        frang_limits {http_strict_host_checking false;}
        
        cache 0;
        block_action error reply;
        block_action attack reply;
    """
}

TEMPESTA_WITH_CACHE = {
    "config": """
        listen ${tempesta_ip}:443 proto=h2;

        server ${server_ip}:8000;
        
        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;
        max_concurrent_streams 10000;
        frang_limits {http_strict_host_checking false;}
        
        cache 2;
        cache_fulfill * *;

        block_action error reply;
        block_action attack reply;
    """
}


@parameterize_class(
    [
        {
            "name": "TfwNoCache",
            "tempesta": TEMPESTA_NO_CACHE,
            "restart_timeout": 10,
            "warm_timeout": 0,
        },
        {
            "name": "TfwWithCache",
            "tempesta": TEMPESTA_WITH_CACHE,
            "restart_timeout": 10,
            "warm_timeout": 0,
        },
        {
            "name": "NoTimeoutTfwNoCache",
            "tempesta": TEMPESTA_NO_CACHE,
            "restart_timeout": 0,
            "warm_timeout": 5,
        },
        {
            "name": "NoTimeoutTfwWithCache",
            "tempesta": TEMPESTA_WITH_CACHE,
            "restart_timeout": 0,
            "warm_timeout": 5,
        },
    ]
)
class TestRebootUnderLoad(tester.TempestaTest):
    """Restart TempestaFW while all the connections are up.

    No crushes must happen.
    """

    clients = [
        {
            "id": "curl",
            "type": "external",
            "binary": "curl",
            "ssl": True,
            "cmd_args": ("-Ikf --http2 https://${tempesta_ip}:443/"),
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

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": ("HTTP/1.1 200 OK\r\n" "Content-length: 0\r\n" "\r\n"),
        },
    ]

    restart_cycles = 10
    restart_timeout = 10

    # Timeout before first reboot.
    warm_timeout = 0

    dbg_msg = "Error for curl"

    def reboot(self) -> None:
        tempesta = self.get_tempesta()
        time.sleep(self.warm_timeout)
        for i in range(self.restart_cycles):
            time.sleep(self.restart_timeout)
            tf_cfg.dbg(3, f"\tReboot {i + 1} of {self.restart_cycles}")
            tempesta.stop()
            # Run random command on remote node to see if it is still alive.
            remote.tempesta.run_cmd("uname")
            tempesta.start()
            self._check_tfw_log()

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

    def test_reboot_under_load(self) -> None:
        # launch all services except clients
        self.start_all_services(client=False)

        # launch h2load
        client = self.get_client("h2load")
        client.start()

        # sending curl requests before reboot Tempesta
        response = self.make_curl_request("curl")
        self.assertIn(STATUS_OK, response, msg=self.dbg_msg)

        self.reboot()

        # sending curl requests after reboot Tempesta
        response = self.make_curl_request("curl")
        self.assertIn(STATUS_OK, response, msg=self.dbg_msg)

        # h2load stop
        self.wait_while_busy(client)
        client.stop()
        self.assertNotIn(" 0 2xx, ", client.response_msg)

    def _check_tfw_log(self) -> None:
        """Checking for errors in the Tempesta log."""
        self.oops.update()
        self.assertFalse(len(self.oops.log_findall("ERROR")))


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
