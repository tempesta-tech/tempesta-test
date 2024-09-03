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


class H2ResponsesPipelinedBase(H2Base):
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

    clients_ids = ["deproxy_1", "deproxy_2", "deproxy_3"]

    def setup_and_start(self, pipelined):
        srv = self.get_server("deproxy")
        srv.pipelined = pipelined
        srv.conns_n = 1
        self.start_all_services()
        return srv


class H2ResponsesPipelined(H2ResponsesPipelinedBase):
    tempesta = {
        "config": """
            listen 443 proto=h2;
            frang_limits {
                http_strict_host_checking false;
            }
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

    def test_success_pipelined(self):
        """
        Send three requests each from the new client.
        Server all responses as pipelined.
        """
        srv = self.setup_and_start(3)

        for id in self.clients_ids:
            client = self.get_client(id)
            client.make_request(self.get_request)

        self.assertTrue(srv.wait_for_requests(3))

        self.assertEqual(len(srv.requests), 3)
        for id in self.clients_ids:
            client = self.get_client(id)
            self.assertEqual(client._last_response.status, "200")

    @parameterize.expand(
        [
            param(name="first_fail", bad_num=1),
            param(name="second_fail", bad_num=2),
            param(name="third_fail", bad_num=3),
        ]
    )
    def test_bad_pipelined(self, name, bad_num):
        srv = self.setup_and_start(3)
        # The next connection will be not pipelined
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
            self.assertTrue(srv.wait_for_requests(i))

        i = 0
        for id in self.clients_ids:
            client = self.get_client(id)
            i = i + 1
            if i == bad_num:
                self.assertEqual(client._last_response.status, "502")
            elif i > bad_num:
                self.assertFalse(client._last_response)
            else:
                self.assertTrue(client.wait_for_response())
                self.assertEqual(client._last_response.status, "200")

        srv.wait_for_connections()
        req_count = i

        i = 0
        j = 0
        for id in self.clients_ids:
            i = i + 1
            client = self.get_client(id)
            if i > bad_num:
                j = j + 1
                self.assertTrue(srv.wait_for_requests(req_count + j))
                srv.flush()
                self.assertTrue(client.wait_for_response())
                self.assertEqual(client._last_response.status, "200")


class H2HmResponsesPipelined(H2ResponsesPipelinedBase):
    tempesta = {
        "config": """
            listen 443 proto=h2;
            frang_limits {
                http_strict_host_checking false;
            }
            
            health_check hm0 {
                request         "GET / HTTP/1.0\r\n\r\n";
                request_url     "/";
                resp_code       200;
                resp_crc32  0x31f37e9f;
                timeout         2;
            }

            srv_group default {
                server ${server_ip}:8000 conns_n=1;
                health hm0;
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

    @parameterize.expand(
        [
            param(name="1_hm", hm_num=1),
            param(name="2_hm", hm_num=2),
            param(name="3_hm", hm_num=3),
            param(name="4_hm", hm_num=4),
        ]
    )
    def test_hm_pipelined(self, name, hm_num):
        srv = self.setup_and_start(4)
        self.disable_deproxy_auto_parser()

        srv.set_response(
            "HTTP/1.1 200 OK\r\n"
            + f"Date: {HttpMessage.date_time_string()}\r\n"
            + "Server: debian\r\n"
            + "Content-Length: 0\r\n\r\n"
        )

        i = 0
        for id in self.clients_ids:
            client = self.get_client(id)
            i = i + 1
            if i == hm_num:
                self.assertTrue(srv.wait_for_requests(i))
                i = i + 1

            client.make_request(self.get_request)
            self.assertTrue(srv.wait_for_requests(i))

        for id in self.clients_ids:
            client = self.get_client(id)
            self.assertTrue(client.wait_for_response())
            self.assertEqual(client._last_response.status, "200")
