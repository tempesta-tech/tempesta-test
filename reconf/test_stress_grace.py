"""
On the fly reconfiguration test for grace shutdown.
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester

NGINX_CONFIG = """
pid ${pid};
worker_processes  auto;

events {
    worker_connections   1024;
    use epoll;
}

http {
    keepalive_timeout ${server_keepalive_timeout};
    keepalive_requests 1000000000;
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
        listen        ${server_ip}:${port};

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
listen 80;
listen 443 proto=h2;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;

cache 0;
server ${server_ip}:8000;
server ${server_ip}:8001;
server ${server_ip}:8002;
server ${server_ip}:8003;
server ${server_ip}:8004;
server ${server_ip}:8005;
server ${server_ip}:8006;
server ${server_ip}:8007;
server ${server_ip}:8008;
server ${server_ip}:8009;

grace_shutdown_time 10;

"""

TEMPESTA_ORIG_CONFIG = """
listen 80;
listen 443 proto=h2;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;

cache 0;

"""

SRV_COUNT = 10


class TestTempestaGraceShutdownReconfig(tester.TempestaTest):
    # 10 backend servers, only difference between them - listen port.
    backends = [
        {
            "id": f"nginx_800{num}",
            "type": "nginx",
            "port": f"800{num}",
            "status_uri": "http://${server_ip}:${port}/nginx_status",
            "config": NGINX_CONFIG,
        }
        for num in range(SRV_COUNT)
    ]

    clients = [
        {
            "id": "client",
            "type": "wrk",
            "addr": "${tempesta_ip}:80",
        },
    ]

    tempesta = {
        "config": TEMPESTA_CONFIG,
    }

    def test_grace_shutdown_reconfig(self):
        """All servers are removed from configuration, but a relatively long
        grace shutdown period is set, since no new sessions are established
        test client should receive just a bit of errors."""

        client = self.get_client("client")
        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()

        self.wait_while_busy(client)

        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(TEMPESTA_ORIG_CONFIG)
        tempesta.reload()


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
