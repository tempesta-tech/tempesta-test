"""Tests for backup server in vhost."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import time

from framework import tester
from helpers import checks_for_tests as checks
from helpers.deproxy import HttpMessage


class ReconnectionLogic(tester.TempestaTest):
    """
    In case of server fails, Tempesta trying to restore the connection.
        During this, it passes three states:
        - Quick:
            Attempts repeat with timeouts less than 1s which gradually increased.
            Client requests waiting for reconnection.
        - Regular:
            Attempts repeat every 1s.
            New client requests are not accepted.
            Timed-out existing requests are evicted.
        - Dead:
            Attempts repeat every 1s.
            Requests rescheduling to backup server
    """

    tempesta = {
        "config": """
listen 80;
listen 443 proto=h2;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;

cache 0;
srv_group primary {server ${server_ip}:8000 conns_n=1;}
srv_group backup {server ${server_ip}:8001 conns_n=1;}
frang_limits {http_strict_host_checking false;}
vhost host {
    proxy_pass primary backup=backup;
}
http_chain {
    -> host;
}
"""
    }

    backends = [
        {
            "id": "primary",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + f"Date: {HttpMessage.date_time_string()}\r\n"
                + "Server: debian\r\n"
                + "Content-Length: 0\r\n\r\n"
            ),
        },
        {
            "id": "backup",
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + f"Date: {HttpMessage.date_time_string()}\r\n"
                + "Server: debian\r\n"
                + "Content-Length: 0\r\n\r\n"
            ),
        },
    ]

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    request = "GET / HTTP/1.1\r\nHost: debian\r\n\r\n"

    def test(self):
        """
        Test reconnecion requests.
        """

        client = self.get_client("deproxy")
        primary_server = self.get_server("primary")
        backup_server = self.get_server("backup")
        tempesta = self.get_tempesta()

        primary_server.conns_n = 1
        backup_server.conns_n = 1

        self.start_all_services()

        client.send_request(self.request, "200")
        self.assertTrue(primary_server.wait_for_responses(1, timeout=1))

        time.sleep(1)

        client.send_request(self.request, "200")
        self.assertTrue(primary_server.wait_for_responses(1, timeout=1))

        primary_server.stop()

        client.send_request(self.request, "200")
        self.assertTrue(backup_server.wait_for_responses(1, timeout=1))

        time.sleep(20)
        tempesta.stop()
