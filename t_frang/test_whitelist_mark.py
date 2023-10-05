"""Tests for Frang directive `whitelist_mark`."""

from framework import deproxy_client, tester
from framework.mixins import NetfilterMarkMixin
from helpers import remote, tempesta, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"


class FrangWhitelistMarkTestCase(tester.TempestaTest, NetfilterMarkMixin):
    clients = [
        {
            "id": "deproxy-cl",
            "type": "deproxy",
            "port": "80",
            "addr": "${tempesta_ip}",
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

    tempesta_template = {
        "config": """
            listen 80;

            frang_limits {
                http_strict_host_checking false;
                http_methods GET;
                http_uri_len 20;
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

    def test_whitelisted_request(self):
        self.start_all_services()

        self.set_nf_mark(1)

        client: deproxy_client.DeproxyClient = self.get_client("deproxy-cl")
        request = client.create_request(uri="/", method="GET", headers=[])
        client.send_request(request, expected_status_code="200")

        client.wait_for_response(1)
        self.assertEqual(client.last_response, 200, "HTTP response status codes mismatch.")
