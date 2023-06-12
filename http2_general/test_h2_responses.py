"""Test module for http2 responses."""
import http

from framework import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"


class H2ResponsesTestCase(tester.TempestaTest, no_reload=True):
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
                proxy_pass default;
            }
            tls_match_any_server_name;
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            cache 0;
            cache_fulfill * *;
            block_action attack reply;
            block_action error reply;
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

    def __setup_h2_responses_test(self):
        curl = self.get_client("curl")
        self.start_all_servers()
        self.start_tempesta()
        return curl

    def __test_h2_response(self, curl, header_name, header_value, status):
        curl.headers[header_name] = header_value
        curl.start()
        self.wait_while_busy(curl)
        curl.stop()
        response = curl.last_response
        self.assertEqual(response.status, status)

    def test_h2_bad_host(self):
        curl = self.__setup_h2_responses_test()
        # perform and check `bad` request
        self.__test_h2_response(curl, "Host", "bad.com", http.HTTPStatus.FORBIDDEN)

    def test_h2_bad_header(self):
        curl = self.__setup_h2_responses_test()

        # perform and check `good` request.
        self.__test_h2_response(curl, "Host", "good.com", http.HTTPStatus.OK)
        # add invalid cookie header and check response.
        self.__test_h2_response(curl, "cookie", "AAAAAA//dfsdf", http.HTTPStatus.BAD_REQUEST)

    def test_h2_bad_forwarded_for_ip(self):
        curl = self.__setup_h2_responses_test()

        # perform request with invalid X-Forwarded-For header
        self.__test_h2_response(curl, "X-Forwarded-For", "1.1.1.1.1.1", http.HTTPStatus.BAD_REQUEST)
