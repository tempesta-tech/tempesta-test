"""Tests for Frang directive `whitelist_mark`."""

from framework import curl_client, deproxy_client, tester
from framework.mixins import NetfilterMarkMixin
from helpers import remote, tempesta, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"


class FrangWhitelistMarkTestCase(tester.TempestaTest, NetfilterMarkMixin):
    clients = [
        # basic request testing
        {
            "id": "deproxy-cl",
            "type": "deproxy",
            "port": "80",
            "addr": "${tempesta_ip}",
        },
        # curl client for connection_rate testing
        {
            "id": "curl-1",
            "type": "curl",
            "addr": "${tempesta_ip}:80",
            "cmd_args": "-v",
            "headers": {
                "Connection": "close",
            },
        },
    ]

    backends = [
        {
            "id": "deproxy-srv",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        },
    ]

    tempesta = {
        "config": """
            listen 80;

            frang_limits {
                http_strict_host_checking false;
                http_methods GET;
                http_uri_len 20;
                connection_rate 1;
            }
            block_action attack reply;
            block_action error reply;

            whitelist_mark 1;

            srv_group sg1 {
                server ${server_ip}:8000;
            }

            vhost vh1 {
                resp_hdr_set Strict-Transport-Security "max-age=31536000; includeSubDomains";
                resp_hdr_set Content-Security-Policy "upgrade-insecure-requests";
                sticky {
                    cookie enforce name=cname;
                    js_challenge resp_code=503 delay_min=1000 delay_range=1500
                    delay_limit=100;
                }
                proxy_pass sg1;
            }

            http_chain {
                -> vh1;
            }
        """,
    }

    def test_non_whitelisted_request(self):
        self.start_all_services()
        client: deproxy_client.DeproxyClient = self.get_client("deproxy-cl")

        client.send_request(
            client.create_request(uri="/", method="GET", headers=[]),
            expected_status_code="503",  # filtered by js_challenge
        )

    def test_whitelisted_request(self):
        self.start_all_services()
        client: deproxy_client.DeproxyClient = self.get_client("deproxy-cl")

        # whitelist_mark 1
        self.set_nf_mark(1)

        # test basic request
        client.send_request(
            client.create_request(uri="/", method="GET", headers=[]),
            expected_status_code="200",
        )
        # test frang http_uri_len
        client.send_request(
            client.create_request(uri="/very-very-long-uri", method="GET", headers=[]),
            expected_status_code="200",
        )
        # test frang connection_rate
        connections = 5
        curl: curl_client.CurlClient = self.get_client("curl-1")
        curl.uri += f"[1-{connections}]"
        curl.parallel = connections
        curl.start()
        self.wait_while_busy(curl)
        curl.stop()
        self.assertEqual(curl.last_response.status, 200)

        # clean up
        self.del_nf_mark(1)
