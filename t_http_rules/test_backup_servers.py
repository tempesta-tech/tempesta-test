"""Tests for backup server in vhost."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester
from helpers import checks_for_tests as checks
from helpers.deproxy import HttpMessage


class HttpRulesBackupServers(tester.TempestaTest):
    tempesta = {
        "config": """
listen 80;        
listen 443 proto=h2;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;

cache 0;
srv_group primary {server ${server_ip}:8000;}
srv_group backup {server ${server_ip}:8001;}

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

    def test_scheduler(self):
        """
        Tempesta must forward requests to backup server if primary server is disabled.
        """
        self.start_all_services()

        client = self.get_client("deproxy")
        primary_server = self.get_server("primary")
        backup_server = self.get_server("backup")

        client.send_request(self.request, "200")
        got_requests = len(primary_server.requests)

        primary_server.stop()
        client.send_request(self.request, "200")

        primary_server.start()
        primary_server.wait_for_connections(3)
        client.send_request(self.request, "200")
        got_requests += len(primary_server.requests)

        self.assertEqual(2, got_requests)
        self.assertEqual(1, len(backup_server.requests))
        checks.check_tempesta_request_and_response_stats(
            tempesta=self.get_tempesta(),
            cl_msg_received=3,
            cl_msg_forwarded=3,
            srv_msg_received=3,
            srv_msg_forwarded=3,
        )
