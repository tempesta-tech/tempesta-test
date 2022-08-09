"""TestCase for mixed listening sockets."""
from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

STATUS_OK = '200'


class TestMixedListeners(tester.TempestaTest):

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
        }

    ]

    clients = [
        {
            'id': 'curl-h2-true',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf --http2 https://127.0.0.4:443/ '
        },
        {
            'id': 'curl-h2-false',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf --http2 https://127.0.0.4:4433/ '
        },
        {
            'id': 'curl-https-true',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf --http1.1 https://127.0.0.4:4433/ '
        },
        {
            'id': 'curl-https-false',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf --http1.1 https://127.0.0.4:443/ '
        },
    ]

    tempesta = {
        'config': """

            listen 127.0.0.4:443 proto=h2;
            listen 127.0.0.4:4433 proto=https;

            srv_group default {
                server ${server_ip}:8000;
            }

            vhost tempesta-cat {
                proxy_pass default;
            }

            tls_match_any_server_name;
            tls_certificate ${tempesta_workdir}/RSA/tfw-root.crt;
            tls_certificate_key ${tempesta_workdir}/RSA/tfw-root.key;

            cache 0;
            cache_fulfill * *;
            block_action attack reply;

            http_chain {
                -> tempesta-cat;
            }

        """
    }

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()

    def test_mixed_h2_success(self):
        """
        Test h2 success situation.

        One `true` client apply h2 client for h2 socket,
        second `false` client apply h2 client for https socket,
        """

        self.start_all()

        curl_h2_true = self.get_client('curl-h2-true')
        curl_h2_true.start()
        self.wait_while_busy(curl_h2_true)
        response = curl_h2_true.resq.get(True, 1)[0].decode()
        self.assertIn(
            STATUS_OK,
            response,
        )
        curl_h2_true.stop()

        curl_h2_false = self.get_client('curl-h2-false')
        curl_h2_false.start()
        self.wait_while_busy(curl_h2_false)
        response = curl_h2_false.resq.get(True, 1)[0].decode()
        self.assertNotIn(
            STATUS_OK,
            response,
        )
        curl_h2_false.stop()

    def test_mixed_https_success(self):
        """
        Test https success situation.

        One `true` client apply https client for https socket,
        second `false` client apply https client for h2 socket,
        """

        self.start_all()

        curl_https_true = self.get_client('curl-https-true')
        curl_https_true.start()
        self.wait_while_busy(curl_https_true)
        response = curl_https_true.resq.get(True, 1)[0].decode()
        self.assertIn(
            STATUS_OK,
            response,
        )
        curl_https_true.stop()

        curl_https_false = self.get_client('curl-https-false')
        curl_https_false.start()
        self.wait_while_busy(curl_https_false)
        response = curl_https_false.resq.get(True, 1)[0].decode()
        self.assertNotIn(
            STATUS_OK,
            response,
        )
        curl_https_false.stop()
