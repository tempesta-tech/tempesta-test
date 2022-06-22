"""Tests for Frang directive `http_header_cnt`."""
from framework import tester
from helpers import dmesg

backends = [
    {
        'id': 'nginx',
        'type': 'nginx',
        'port': '8000',
        'status_uri': 'http://${server_ip}:8000/nginx_status',
        'config': """
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
                error_log /dev/null emerg;
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
        """,
    },
]

clients = [
    {
        'id': 'curl-1',
        'type': 'external',
        'binary': 'curl',
        'ssl': True,
        'cmd_args': '-Ikf -v --http2 https://127.0.0.4:443/ -H "Host: tempesta-tech.com" -H "User-agent: {0}"'.format(
            '123' * 10000,
        ),
    },
]

tempesta_conf = """
frang_limits {
    http_header_cnt 20;
}

listen 127.0.0.4:443 proto=h2;

srv_group default {
    server ${server_ip}:8000;
}

vhost tempesta-cat {
    proxy_pass default;
}

tls_match_any_server_name;
tls_certificate RSA/tfw-root.crt;
tls_certificate_key RSA/tfw-root.key;

cache 0;
cache_fulfill * *;
block_action attack reply;

http_chain {
    -> tempesta-cat;
}
"""


class FrangHeaderCntTestCase(tester.TempestaTest):
    """Tests 'http_header_cnt' directive."""

    header_cnt = 20

    clients = clients

    backends = backends

    tempesta = {
        'config': tempesta_conf,
    }

    def setUp(self):
        """Set up test."""
        super().setUp()
        self.klog = dmesg.DmesgFinder(ratelimited=False)

    def test_test(self):
        curl = self.get_client('curl-1')

        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()

        curl.start()
        self.wait_while_busy(curl)

        print(
            curl.resq.get(True, 1)[0].decode(),
        )

        curl.stop()
