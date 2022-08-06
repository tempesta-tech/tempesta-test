"""Test module for http2 and Sticky Cookie."""
from framework import tester


class H2StickyCookieTestCase(tester.TempestaTest):
    """Sticky Cookie H2 test case."""

    clients = [
        {
            'id': 'curl-1',
            'type': 'external',
            'binary': 'curl',
            'ssl': True,
            'cmd_args': '-Ikf -v --http2 https://127.0.0.4:8765/ -H "Host: tempesta-tech.com:8765"',  # noqa:E501
        },
    ]

    tempesta = {
        'config': """
            listen 127.0.0.4:8765 proto=h2;

            sticky {
                cookie name=__test;
            }

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
        """,
    }

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

    def test_h2_cookie_default(self):
        curl = self.get_client('curl-1')

        self.start_all_servers()
        self.start_tempesta()

        curl.start()
        self.wait_while_busy(curl)

        curl.stop()

