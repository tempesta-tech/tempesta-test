__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

from pathlib import Path

from framework.helpers import remote, tf_cfg
from framework.test_suite import tester


class TestSlowRead(tester.TempestaTest):
    clients = [
        {
            "id": f"deproxy-{i}",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        }
        for i in range(20)
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

        """
    }

    response_file_name = "large.txt"
    response_file_path = str(Path(tf_cfg.cfg.get("Server", "resources")) / response_file_name)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        remote.server.run_cmd(
            f"fallocate -l {1024**2 * int(tf_cfg.cfg.get("General", "long_body_size"))} {cls.response_file_path}"
        )

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        remote.server.remove_file(cls.response_file_path)

    def test_cve_2019_9511(self):
        """
        CVE-2019-9511 - “Data Dribble”
        Some HTTP/2 implementations are vulnerable to window size manipulation
        and stream prioritization manipulation, potentially leading to a denial of service.
        The attacker requests a large amount of data from a specified resource over multiple streams.
        They manipulate window size and stream priority to force the server to queue the data in 1-byte chunks.
        Depending on how efficiently this data is queued, this can consume excess CPU, memory, or both.
        """
        self.start_all_services()

        request = self.get_clients()[0].create_request(
            method="GET",
            headers=[],
            authority="tempesta-tech.com",
            uri=f"/{self.response_file_name}",
        )

        for client in self.get_clients():
            client.update_initial_settings(initial_window_size=1)
            client.send_bytes(client.h2_connection.data_to_send())
            self.assertTrue(client.wait_for_ack_settings())
            client.make_requests([request] * 100)

        for client in self.get_clients():
            client.wait_for_connection_close(strict=True)

    def test_cve_2019_9517(self):
        """
        CVE-2019-9517 - “Internal Data Buffering”
        Some HTTP/2 implementations are vulnerable to unconstrained internal data buffering,
        potentially leading to a denial of service. The attacker opens the HTTP/2 window
        so the peer can send without constraint; however, they leave the TCP window closed
        so the peer cannot actually write (many of) the bytes on the wire.
        The attacker sends a stream of requests for a large response object.
        Depending on how the servers queue the responses, this can consume excess memory, CPU, or both.
        """
        self.start_all_services()

        request = self.get_clients()[0].create_request(
            method="GET",
            headers=[],
            authority="tempesta-tech.com",
            uri=f"/{self.response_file_name}",
        )

        for client in self.get_clients():
            client.update_initial_settings()
            client.send_bytes(client.h2_connection.data_to_send())
            self.assertTrue(client.wait_for_ack_settings())
            client.set_size_of_receiving_buffer(new_buffer_size=1)
            client.make_requests([request] * 100)

        for client in self.get_clients():
            client.wait_for_connection_close(timeout=20, strict=True)
