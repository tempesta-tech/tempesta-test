"""Test module for http2 and Sticky Cookie Scheduler."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import http

from framework import tester
from helpers import dmesg


class H2StickySchedulerTestCase(tester.TempestaTest):
    """Sticky Cookie H2 test case."""

    clients = [
        {
            "id": "curl",
            "type": "curl",
            "http2": True,
            "addr": "${tempesta_ip}:8765",
        },
    ]

    tempesta = {
        "config": """
            listen ${tempesta_ip}:8765 proto=h2;

            srv_group default {
                server ${server_ip}:8000;
            }

            vhost v_good {
                frang_limits {http_strict_host_checking false;}
                proxy_pass default;
                sticky {
                    sticky_sessions;
                    cookie enforce;
                    secret "f00)9eR59*_/22";
                }
            }
            tls_match_any_server_name;
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            cache 1;
            cache_fulfill * *;
            block_action attack reply;
            http_chain {
                host == "bad.com"	-> block;
                host == "good.com" -> v_good;
            }
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

    @dmesg.unlimited_rate_on_tempesta_node
    def test_h2_cookie_scheduler(self):
        """
        Test for sticky cookie scheduler by issue.

        Cookies are taken from response.

        1. client request URI with Host http://good.com/
        2. tempesta responds with 302 and sticky cookie
        3. client repeat the request with sticky cookie set
        4. tempesta forwards the request to server and
        forwards its response to the client with 200
        5. client requests URI with Host http://bad.com/ with sticky cookie set
        6. tempesta filtering out request

        """
        curl = self.get_client("curl")

        self.start_all_servers()
        self.start_tempesta()

        # perform `init` request
        curl.headers = {"Host": "good.com"}
        curl.start()
        self.wait_while_busy(curl)
        curl.stop()
        response = curl.last_response
        self.assertEqual(response.status, http.HTTPStatus.FOUND)
        self.assertIn("__tfw", response.headers["set-cookie"])

        # perform `good` request
        curl.headers = {
            "Host": "good.com",
            "Cookie": response.headers["set-cookie"],
        }

        curl.start()
        self.wait_while_busy(curl)
        curl.stop()

        response = curl.last_response
        self.assertEqual(response.status, http.HTTPStatus.OK)

        # perform `bad` request
        curl.headers["Host"] = "bad.com"
        curl.start()
        self.wait_while_busy(curl)
        curl.stop()
        response = curl.last_response
        self.assertEqual(response.status, http.HTTPStatus.FORBIDDEN)

        # check request is filtering out
        self.assertTrue(
            self.oops.find(
                "request has been filtered out via http table",
            ),
            "Filtered request warning is not shown",
        )
