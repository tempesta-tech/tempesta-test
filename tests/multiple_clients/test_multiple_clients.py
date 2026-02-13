__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework.deproxy import deproxy_message
from framework.test_suite import tester


class TestMultipleClients(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + f"Date: {deproxy_message.HttpMessage.date_time_string()}\r\n"
                + "Server: debian\r\n"
                + "Content-Length: 0\r\n\r\n"
            ),
        }
    ]

    tempesta = {
        "config": """
listen 443 proto=https;

client_lru_size 1;

block_action error reply;
block_action attack reply;
access_log off;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;

server ${server_ip}:8000;
""",
    }

    clients_n = 20

    clients = [
        {
            "id": f"deproxy-{n}",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "interface": True,
        }
        for n in range(clients_n)
    ]

    def test(self):
        """
        Run several clients from different ips. Since `client_lru_size` is equal to 1
        Tempesta FW client free list has only one element and will be exceeded when
        second client will be connected. First client should not be removed from client
        database, otherwise if client connection hung we can't destroy it during Tempesta
        FW stopping.
        """
        self.start_all_services()
        request = self.get_client("deproxy-0").create_request(
            method="GET", headers=[("Content-Type", "invalid")]
        )

        for client in self.get_clients():
            client.not_close_connection_for_fin = True

        for client in self.get_clients():
            client.send_request(request)

        self.get_tempesta().stop()
