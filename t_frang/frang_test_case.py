"""Frang Test Case."""
from framework import tester
from helpers import dmesg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"

DELAY = 0.125  # delay for bursting logic
ASSERT_MSG = "Expected nums of warnings in `journalctl`: {exp}, but got {got}"


class FrangTestCase(tester.TempestaTest):
    """
    Frang Test case class, defined the backend in tests
    """

    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
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

    def setUp(self):
        super().setUp()
        self.klog = dmesg.DmesgFinder(ratelimited=False)
        self.assert_msg = ASSERT_MSG
