"""
TLS perf tests - load Tempesta FW with multiple TLS handshakes.
"""

import helpers.tf_cfg as tf_cfg
from framework import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2020 Tempesta Technologies, Inc."
__license__ = "GPL2"

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
"""

TEMPESTA_CONFIG = """
listen 443 proto=h2;
srv_group default {
    server ${server_ip}:8000;
}
vhost default {
    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;
    tls_match_any_server_name;

    proxy_pass default;
}
"""


class TLSPerf(tester.TempestaTest):
    clients = [
        {
            "id": "tls-perf",
            "type": "external",
            "binary": "tls-perf",
            "cmd_args": (
                "-c ECDHE-ECDSA-AES128-GCM-SHA256 -C prime256v1 -l 1000 -t 2 -T %s ${server_ip} 443"
                % (tf_cfg.cfg.get("General", "Duration"))
            ),
        },
    ]

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG,
        }
    ]

    tempesta = {
        "config": TEMPESTA_CONFIG,
    }

    def test(self):
        tls_perf = self.get_client("tls-perf")

        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.wait_while_busy(tls_perf)
