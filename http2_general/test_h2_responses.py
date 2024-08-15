"""Test module for http2 responses."""

import http
import time

from framework import tester
from framework.parameterize import param, parameterize
from http2_general.helpers import H2Base
from helpers.deproxy import HttpMessage

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"


class H2ResponsesTestCase(tester.TempestaTest):
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

            frang_limits {http_strict_host_checking false;}
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


class H2ResponsesPipelined(H2Base):
    clients = [
        {
            "id": "deproxy_1",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "deproxy_2",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "deproxy_3",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]

    tempesta = {
        "config": """
            listen 443 proto=h2;
            srv_group default {
                server ${server_ip}:8000 conns_n=1;
            }
            vhost good {
                proxy_pass default;
            }
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;
            http_max_header_list_size 134217728; #128 KB

            block_action attack reply;
            block_action error reply;
            http_chain {
                host == "bad.com"   -> block;
                                    -> good;
            }
        """
    }

    clients_ids = ["deproxy_1", "deproxy_2", "deproxy_3"]

    def __setup_and_start(self):
        srv = self.get_server("deproxy")
        srv.pipelined = 3
        srv.conns_n = 1
        self.start_all_services()
        return srv

    def test_success_pipelined(self):
        """
        Send three requests each from the new client.
        Server all responses as pipelined.
        """
        srv = self.__setup_and_start()

        for id in self.clients_ids:
            client = self.get_client(id)
            client.make_request(self.get_request)

        time.sleep(3)

        self.assertEqual(len(srv.requests), 3)
        for id in self.clients_ids:
            client = self.get_client(id)
            self.assertEqual(client._last_response.status, "200")

    @parameterize.expand(
        [
            param(name="1", bad_num=1),
            param(name="2", bad_num=2),
            param(name="3", bad_num=3),
        ]
    )
    def test_bad_pipelined(self, name, bad_num):
        srv = self.__setup_and_start()
        self.disable_deproxy_auto_parser()

        i = 0
        for id in self.clients_ids:
            client = self.get_client(id)
            i = i + 1
            if i == bad_num:
                srv.set_response(
                    "HTTP/1.1 200 OK\r\n"
                    + f"Date: {HttpMessage.date_time_string()}\r\n"
                    + "Server: debian\r\n"
                    + "C ontent-Length: 0\r\n\r\n"
                )
            else:
                srv.set_response(
                    "HTTP/1.1 200 OK\r\n"
                    + f"Date: {HttpMessage.date_time_string()}\r\n"
                    + "Server: debian\r\n"
                    + "Content-Length: 0\r\n\r\n"
                )
            client.make_request(self.get_request)
            # Make sure that server receive request and use appropriate
            # response.
            time.sleep(1)

        time.sleep(1)

        self.assertEqual(len(srv.requests), 3)

        i = 0
        for id in self.clients_ids:
            client = self.get_client(id)
            i = i + 1
            if i >= bad_num:
                self.assertEqual(client._last_response.status, "502")
            else:
                self.assertEqual(client._last_response.status, "200")
