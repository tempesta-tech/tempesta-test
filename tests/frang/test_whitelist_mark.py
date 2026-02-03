"""Tests for Frang directive `whitelist_mark`."""

from framework.deproxy import deproxy_client
from framework.helpers import remote, tf_cfg
from framework.helpers.mixins import NetfilterMarkMixin
from framework.services import curl_client
from framework.test_suite import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"


class FrangWhitelistMarkTestCase(NetfilterMarkMixin, tester.TempestaTest):
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
                tcp_connection_rate 1;
            }
            block_action attack reply;
            block_action error reply;

            whitelist_mark 1;

            srv_group sg1 {
                server ${server_ip}:8000;
            }

            vhost vh1 {
                sticky {
                    cookie enforce name=cname;
                    js_challenge resp_code=503 delay_min=1000 delay_range=1500
                    ${tempesta_workdir}/js_challenge.html;
                }
                proxy_pass sg1;
            }

            http_chain {
                -> vh1;
            }
        """,
    }

    def prepare_js_templates(self):
        srcdir = tf_cfg.cfg.get("Tempesta", "srcdir")
        workdir = tf_cfg.cfg.get("Tempesta", "workdir")
        template = "%s/etc/js_challenge.tpl" % srcdir
        js_code = "%s/etc/js_challenge.js.tpl" % srcdir
        remote.tempesta.run_cmd("cp %s %s" % (js_code, workdir))
        remote.tempesta.run_cmd("cp %s %s/js_challenge.tpl" % (template, workdir))

    def setUp(self):
        self.prepare_js_templates()
        return super().setUp()

    def test_whitelisted_basic_request(self):
        self.set_nf_mark(1)
        self.start_all_services(client=False)

        client: deproxy_client.DeproxyClient = self.get_client("deproxy-cl")
        client.start()
        client.send_request(
            client.create_request(uri="/", method="GET", headers=[]),
            expected_status_code="200",
        )

    def test_whitelisted_basic_request_xforwarded_for(self):
        self.set_nf_mark(1)
        self.start_all_services(client=False)

        client: deproxy_client.DeproxyClient = self.get_client("deproxy-cl")
        client.start()
        client.send_request(
            client.create_request(uri="/", method="GET", headers=[("x-forwarded-for", "1.2.3.4")]),
            expected_status_code="200",
        )

    def test_whitelisted_frang_http_uri_len(self):
        self.set_nf_mark(1)
        self.start_all_services(client=False)

        client: deproxy_client.DeproxyClient = self.get_client("deproxy-cl")
        client.start()
        client.send_request(
            # very long uri
            client.create_request(uri="/" + "a" * 25, method="GET", headers=[]),
            expected_status_code="200",
        )

    def test_whitelisted_frang_http_uri_len_xforwarded_for(self):
        self.set_nf_mark(1)
        self.start_all_services(client=False)

        client: deproxy_client.DeproxyClient = self.get_client("deproxy-cl")
        client.start()
        client.send_request(
            # very long uri
            client.create_request(
                uri="/" + "a" * 25, method="GET", headers=[("x-forwarded-for", "1.2.3.4")]
            ),
            expected_status_code="200",
        )

    def test_whitelisted_frang_connection_rate(self):
        self.set_nf_mark(1)

        connections = 5
        curl: curl_client.CurlClient = self.get_client("curl-1")
        curl.uri += f"[1-{connections}]"
        curl.parallel = connections
        curl.dump_headers = False

        self.start_all_services()

        curl.start()
        self.wait_while_busy(curl)
        curl.stop()
        # we expect all requests to receive 200
        self.assertEqual(
            curl.statuses,
            {200: connections},
            "Client is whitelisted, but connection rate is still aplied.",
        )

    def test_non_whitelisted_request_are_js_challenged(self):
        self.start_all_services(client=False)

        client: deproxy_client.DeproxyClient = self.get_client("deproxy-cl")
        client.start()
        client.send_request(
            client.create_request(uri="/", method="GET", headers=[]),
            expected_status_code="403",
        )
