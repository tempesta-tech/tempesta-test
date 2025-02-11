__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

import os
from pathlib import Path

from framework import tester
from helpers import tf_cfg


class TestH2SlowRead(tester.TempestaTest):
    parallel = 10
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

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": """
pid ${pid};
worker_processes  auto;

events {
    worker_connections   1024;
    use epoll;
}

http {
    keepalive_timeout ${server_keepalive_timeout};
    keepalive_requests 10;
    sendfile         on;
    tcp_nopush       on;
    tcp_nodelay      on;

    open_file_cache max=1000;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors off;

    # [ debug | info | notice | warn | error | crit | alert | emerg ]
    # Fully disable log errors.
    error_log /dev/null emerg;

    # Disable access log altogether.
    access_log off;

    server {
        listen        ${server_ip}:8000;

        location / {
            root ${server_resources};
        }
        location /nginx_status {
            stub_status on;
        }
    }
}
""",
        }
    ]

    tempesta = {
        "config": """
        cache 0;
        keepalive_timeout 10;
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

        frang_limits {
            # TODO tempesta#498: remove the body length limit
            http_body_len 1000000;
        }
        """
    }

    def setUp(self):
        super().setUp()

        BODY_SIZE = 1024 * 1024 * 100  # 100MB
        body = "x" * BODY_SIZE

        fp = str(Path(tf_cfg.cfg.get("Server", "resources")) / "large.file")
        with open(fp, "w") as f:
            f.write(body)

        self.addCleanup(lambda: os.remove(fp))

    def test_window_update(self):
        self.start_all_services()

        for client in self.get_clients():
            client.update_initial_settings(initial_window_size=1)
            client.send_bytes(client.h2_connection.data_to_send())
            self.assertTrue(client.wait_for_ack_settings())
            for _ in range(100):
                # send HEADERS frame with END_STREAM flag
                client.make_request(
                    client.create_request(
                        method="GET", headers=[], authority="tempesta-tech.com", uri="/large.file"
                    ),
                    end_stream=True,
                )

        for client in self.get_clients():
            self.assertTrue(client.wait_for_connection_close())

    def test_tcp(self):
        self.start_all_services()

        for client in self.get_clients():
            client.update_initial_settings(initial_window_size=(1 << 31) - 10)
            client.send_bytes(client.h2_connection.data_to_send())
            self.assertTrue(client.wait_for_ack_settings())
            client.readable = lambda: False
            for _ in range(100):
                client.make_request(
                    client.create_request(
                        method="GET", headers=[], authority="tempesta-tech.com", uri="/large.file"
                    ),
                    end_stream=True,
                )

        for client in self.get_clients():
            self.assertFalse(client.wait_for_response(10))
            client.readable = lambda: True
            self.assertTrue(client.wait_for_connection_close())
