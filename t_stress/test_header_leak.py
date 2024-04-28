__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

import random
import string
from threading import Thread

from framework import tester


def randomword(length):
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(length))


class TestH2HeaderLeak(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        }
    ]

    tempesta = {
        "config": """
        cache 0;

        keepalive_timeout 1000;

        listen 443 proto=h2;

        tls_match_any_server_name;

        srv_group default {
            server ${server_ip}:8000;
        }

        vhost tempesta-tech.com {
           tls_certificate ${tempesta_workdir}/tempesta.crt;
           tls_certificate_key ${tempesta_workdir}/tempesta.key;
           proxy_pass default;
        }
        """
    }

    parallel = 3
    clients = [
        {
            "id": f"deproxy-{i}",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        }
        for i in range(parallel)
    ]

    def test(self):
        self.start_all_services()

        headers = [
            (":method", "GET"),
            (":path", "/"),
            (":authority", "tempesta-tech.com"),
            (":scheme", "https"),
        ]

        # memory leak even after the connection closed, if too many big headers
        for _ in range(50):
            headers.append((randomword(100), randomword(100)))

        def run_test(client):
            # memory grow until OOM even if one active stream at one time
            for _ in range(100_0000):
                client.send_request(headers, "200")

        pool = []
        for client in self.get_clients():
            p = Thread(target=run_test, args=(client,))
            p.start()
            pool.append(p)
        for p in pool:
            p.join()
