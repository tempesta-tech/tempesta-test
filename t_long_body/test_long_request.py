"""Tests for long body in request."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import os

from helpers import remote, tf_cfg
from helpers.networker import NetWorker
from test_suite import checks_for_tests as checks
from test_suite.tester import TempestaTest

BODY_SIZE = 1024**2 * int(tf_cfg.cfg.get("General", "long_body_size"))

NGINX_CONFIG = """
pid ${pid};
worker_processes  auto;

events {
    worker_connections   1024;
    use epoll;
}

http {
    keepalive_timeout ${server_keepalive_timeout};
    keepalive_requests ${server_keepalive_requests};
    sendfile         on;
    tcp_nopush       on;
    tcp_nodelay      on;

    open_file_cache max=1000;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors off;
    client_max_body_size 10000M;

    # [ debug | info | notice | warn | error | crit | alert | emerg ]
    # Fully disable log errors.
    error_log /dev/null emerg;

    # Disable access log altogether.
    access_log off;

    server {
        listen        ${server_ip}:8000;

        chunked_transfer_encoding on;
        location / {
            return 200;

        }
        location /nginx_status {
            stub_status on;
        }
    }
}
"""


class LongBodyInRequest(TempestaTest):
    tempesta = {
        "config": """
    listen 80;
    listen 443 proto=https;
    listen 4433 proto=h2;

    server ${server_ip}:8000;

    frang_limits {http_strict_host_checking false;}
    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;
    tls_match_any_server_name;
    cache 0;
    """
    }

    clients = [
        {
            "id": "curl-http",
            "type": "curl",
            "addr": "${tempesta_ip}:80",
        },
        {
            "id": "curl-https",
            "type": "curl",
            "addr": "${tempesta_ip}:443",
            "ssl": True,
        },
        {
            "id": "curl-h2",
            "type": "curl",
            "addr": "${tempesta_ip}:4433",
            "http2": True,
        },
    ]

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG,
        },
    ]

    def setUp(self):
        location = tf_cfg.cfg.get("Client", "workdir")
        self.abs_path = os.path.join(location, "long_body.bin")
        remote.client.copy_file(self.abs_path, "x" * BODY_SIZE)
        super().setUp()
        # Cleanup part
        self.addCleanup(self.cleanup_file)

    def cleanup_file(self):
        if not remote.DEBUG_FILES:
            remote.client.run_cmd(f"rm {self.abs_path}")

    @NetWorker.set_mtu(
        nodes=[
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Client", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.tempesta",
                "destination_ip": tf_cfg.cfg.get("Server", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
            {
                "node": "remote.server",
                "destination_ip": tf_cfg.cfg.get("Tempesta", "ip"),
                "mtu": int(tf_cfg.cfg.get("General", "stress_mtu")),
            },
        ]
    )
    def _test(self, client_id: str, header: str):
        """Send request with long body and check that Tempesta does not crash."""
        self.start_all_services(client=False)

        client = self.get_client(client_id)
        client.options = [f" --data-binary @'{self.abs_path}' -H '{header}' -H 'Expect: '"]
        client.start()
        client.wait_for_finish()
        client.stop()

        self.assertIsNotNone(client.last_response)
        self.assertEqual(client.last_response.status, 200)
        tempesta = self.get_tempesta()
        tempesta.get_stats()

        checks.check_tempesta_request_and_response_stats(
            tempesta=self.get_tempesta(),
            cl_msg_forwarded=1,
            cl_msg_received=1,
            srv_msg_received=1,
            srv_msg_forwarded=1,
        )

    def test_http(self):
        self._test(client_id="curl-http", header=f"Content-Length: {BODY_SIZE}")

    def test_https(self):
        self._test(client_id="curl-https", header=f"Content-Length: {BODY_SIZE}")

    def test_h2(self):
        self._test(client_id="curl-h2", header=f"Content-Length: {BODY_SIZE}")

    def test_many_big_chunks_in_request_http(self):
        self._test(
            client_id="curl-http",
            header="Transfer-Encoding: chunked",
        )

    def test_many_big_chunks_in_request_https(self):
        self._test(
            client_id="curl-https",
            header="Transfer-Encoding: chunked",
        )
