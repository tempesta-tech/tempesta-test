"""Tests for Frang directive `request_rate` and 'request_burst'."""
import time

from framework import tester
from helpers import dmesg

ONE = 1
ZERO = 0
DELAY = 0.125
ASSERT_MSG = 'Expected nums of warnings in `journalctl`: {exp}, but got {got}'
ERROR_RATE = 'Warning: frang: request rate exceeded for'
ERROR_BURST = 'Warning: frang: requests burst exceeded for'


class FrangRequestRateTestCase(tester.TempestaTest):
    """Tests for 'request_rate' and 'request_burst' directive."""

    clients = [
        {
            'id': 'curl-1',
            'type': 'external',
            'binary': 'curl',
            'cmd_args': '-Ikf -v http://127.0.0.4:8765/ -H "Host: tempesta-tech.com:8765"',  # noqa:E501
        },
    ]

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

    tempesta = {
        'config': """
            frang_limits {
                request_rate 4;
                request_burst 2;
            }
            listen 127.0.0.4:8765;
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

    def setUp(self):
        """Set up test."""
        super().setUp()
        self.klog = dmesg.DmesgFinder(ratelimited=False)

    def test_request_rate(self):
        """Test 'request_rate'."""
        curl = self.get_client('curl-1')

        self.start_all_servers()
        self.start_tempesta()

        # request_rate 4; in tempesta, increase to catch limit
        request_rate = 5

        for step in range(request_rate):
            print(step)
            curl.start()
            self.wait_while_busy(curl)


            # delay to split tests for `rate` and `burst`
            time.sleep(DELAY)

            curl.stop()
            response = curl.proc_results
            print(response)
