import socket
import ssl
import threading
import time

from framework.deproxy import deproxy_message
from framework.helpers import networker, remote
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

srv_group grp1 {
    server ${server_ip}:8000;
}

vhost test {
    proxy_pass grp1;
}

http_chain {
    host == "bad.com"   -> block;
    -> test;
}
""",
    }

    stop = False
    wait_for_fin = 0
    hung_threads = []

    def ___hung_client(self, number_of_ip):
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["http/1.1"])
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection(
            ("tempesta-tech.com", 443), source_address=(f"127.0.0.{number_of_ip}", 0)
        )
        tls = ctx.wrap_socket(sock, server_hostname="tempesta-tech.com")

        tls.sendall(b"GET / HTTP/1.1\r\n" b"Content-Type: invalid\r\n" b"\r\n")

        # Read until server closes (FIN)
        while True:
            data = tls.recv(4096)
            if not data:
                break

        self.wait_for_fin += 1

        while not self.stop:
            pass

    def __finish_hung_clients(self):
        self.stop = True
        for t in self.hung_threads:
            t.join()

    def setUp(self):
        super().setUp()
        self.addCleanup(self.__finish_hung_clients)

    def test(self):
        """
        Run several clients from different ips. Since `client_lru_size` is equal to 1
        Tempesta FW client free list has only one element and will be exceeded when
        second client will be connected. First client should not ne removed from client
        database, otherwise if client connection hung we can't destroy it during Tempesta
        FW stopping.
        """
        self.start_all_services()
        count_of_clients = 20

        with networker.create_and_cleanup_interfaces(
            node=remote.tempesta, number_of_ip=count_of_clients
        ) as ips:
            for number_of_ip in range(count_of_clients):
                t = threading.Thread(target=self.___hung_client, args=(number_of_ip,))
                self.hung_threads.append(t)

            for t in self.hung_threads:
                t.start()

            while self.wait_for_fin < count_of_clients:
                pass

            self.get_tempesta().stop()
