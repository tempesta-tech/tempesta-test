from framework import tester
from helpers import tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
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
            return 200;
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

    proxy_pass default;
}

cache 0;

"""


class H2Spec(tester.TempestaTest):
    """Tests for h2 proto implementation. Run h2spec utility against Tempesta.
    Simply check return code and warnings in system log for test errors.
    """

    clients = [
        {
            "id": "h2spec",
            "type": "external",
            "binary": "h2spec",
            "ssl": True,
            "cmd_args": "-tkh ${tempesta_ip}",
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

    def test_h2_specs(self):
        h2spec = self.get_client("h2spec")
        # For different reasons there's still a bunch of `h2spec` tests that fail.
        # To let the vast majority of the remaining passing test to work and help us catch
        # unexpected regressions, we only disable some specific tests. We will enable those
        # again after Tempesta gets required updates.
        # FYI: there are tests that would fail just occasionally, not every time, so please
        # before enabling a test from this list, ensure that it actually passes a decent
        # amount of runs in a row.
        h2spec.options.extend(
            [
                "-x generic/2/2",
                "-x generic/2/3",
                "-x generic/3.10/2",
                "-x http2/4.3/3",
                "-x http2/5.1/5",
                "-x http2/5.1/6",
                "-x http2/5.1/11",
                "-x http2/5.1/12",
                "-x http2/5.1.1/4",
                "-x http2/5.3.1/1",  # causes dmesg warning
                "-x http2/5.3.1/2",
                "-x http2/5.5/2",
                "-x http2/6.1/2",
                "-x http2/6.2/2",
                "-x http2/6.9.1/2",
                "-x http2/6.9.1/3",
                "-x http2/8.1/1",
                "-x http2/8.1.2/1",
                "-x http2/8.1.2.1/3",  # causes dmesg warning
                "-x http2/8.1.2.2/2",
                "-x http2/8.1.2.3/5",  # causes dmesg warning
                "-x http2/8.1.2.3/6",  # causes dmesg warning
                "-x http2/8.1.2.3/7",  # causes dmesg warning
                "-x hpack/4.2/1",
                "-x hpack/5.2/3",  # causes dmesg warning
            ]
        )

        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.wait_while_busy(h2spec)
        self.assertEqual(0, h2spec.returncode)


class H2Load(tester.TempestaTest):
    """Tests for h2 proto implementation. Run h2load utility against Tempesta.
    Simply check return code and warnings in system log for test errors.
    """

    clients = [
        {
            "id": "h2load",
            "type": "external",
            "binary": "h2load",
            "ssl": True,
            "cmd_args": " https://${tempesta_ip} -D100",
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

    def test_h2_specs(self):
        h2load = self.get_client("h2load")

        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.wait_while_busy(h2load)
