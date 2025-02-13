"""Tests for backup server in vhost."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from helpers.deproxy import HttpMessage
from test_suite import tester


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
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    def test_reconnection_to_primary_server(self):
        """
        TempestaFW must reconnect to primary server if the server is active again.
        """

        client = self.get_client("deproxy")
        primary_server = self.get_server("primary")
        backup_server = self.get_server("backup")
        request = client.create_request(method="GET", uri="/", headers=[])

        primary_server.conns_n = 1
        backup_server.conns_n = 1

        self.start_all_services()

        client.send_request(request, "200")
        self.assertTrue(
            primary_server.wait_for_requests(1),
            "TempestaFW first send a request to the backup server.",
        )

        primary_server.stop()

        client.send_request(request, "200")
        self.assertTrue(
            backup_server.wait_for_requests(1),
            "TempestaFW doesn't send a request to the backup server when the primary server is down.",
        )

        primary_server.start()
        self.assertTrue(
            primary_server.wait_for_connections(),
            "TempestaFW doesn't reconnect to the primary server.",
        )
        self.assertEqual(
            len(primary_server.requests), 0, "Server must remove the old requests after restart."
        )

        client.send_request(request, "200")
        self.assertTrue(
            primary_server.wait_for_requests(1),
            "TempestaFW doesn't send a request to the primary server "
            "when it has restored operation.",
        )
        self.assertLess(
            len(backup_server.requests), 2, "TempestaFW duplicated the request to the backup server"
        )
