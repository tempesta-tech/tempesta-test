"""Test module for http2 responses."""
import http

from framework import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"


class H2CachedResponsesTestCase(tester.TempestaTest):
    clients = [
        {
            "id": "curl",
            "type": "curl",
            "http2": True,
            "addr": "${tempesta_ip}:8765",
        },
    ]

    # TODO
    # We must check all possible values of
    # block_action attack and block_action error
    tempesta = {
        "config": """
            listen ${tempesta_ip}:8765 proto=h2;
            server ${server_ip}:8000;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;

            vhost default {
                resp_hdr_add x-my-hdr "Custom Header In Mixed Case";
            }

            cache 2;
            cache_fulfill * *;
            
        """,
    }

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

    def test_h2_cached_response_with_headers_modification(self):
        curl = self.get_client("curl")
        self.start_all_servers()
        self.start_tempesta()

        curl.start()
        self.wait_while_busy(curl)
        curl.stop()
        response = curl.last_response
        self.assertEqual(response.status, http.HTTPStatus.OK)


        curl.start()
        self.wait_while_busy(curl)
        curl.stop()
        response = curl.last_response
        self.assertEqual(response.status, http.HTTPStatus.OK)