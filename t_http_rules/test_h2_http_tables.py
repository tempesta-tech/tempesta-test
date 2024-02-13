"""H2 tests for http tables. See test_http_tables.py."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

import copy

from framework import tester
from t_http_rules import test_http_tables


class TestHttpTablesH2(test_http_tables.HttpTablesTest):
    request = [
        (":scheme", "https"),
        (":method", "GET"),
    ]

    def setUp(self):
        self.clients = copy.deepcopy(self.clients)
        for client in self.clients:
            client["port"] = "443"
            client["type"] = "deproxy_h2"
            client["ssl"] = True
        super(TestHttpTablesH2, self).setUp()

    def process(self, client, server, chain, step):
        option = self.requests_opt[step]
        client.send_request(
            request=(
                self.request
                + [
                    (":authority", option[2] if option[1] == "host" else "localhost"),
                    (":path", option[0]),
                    (option[1], option[2]),
                ]
            ),
            expected_status_code="403" if option[3] and self.match_rules_test else "200",
        )

        if client.last_response.status == "200":
            self.assertIsNotNone(server.last_request)
            self.assertIn((option[1], option[2]), server.last_request.headers.items())
        else:
            self.assertIsNone(server.last_request)
            self.assertTrue(client.wait_for_connection_close())


class HttpTablesTestMarkRulesH2(TestHttpTablesH2, test_http_tables.HttpTablesTestMarkRules):
    match_rules_test = False


class H2Config:
    requests = [
        (":authority", "tempesta-tech.com"),
        (":path", "/"),
        (":scheme", "https"),
        (":method", "GET"),
    ]

    clients = [
        {
            "id": "client",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]


class HttpTablesTestEmptyMainChainReplyH2(
    H2Config, test_http_tables.HttpTablesTestEmptyMainChainReply
):
    pass


class HttpTablesTestEmptyMainChainDropH2(
    H2Config, test_http_tables.HttpTablesTestEmptyMainChainDrop
):
    pass


class HttpTablesTestEmptyMainChainDefaultH2(
    H2Config, test_http_tables.HttpTablesTestEmptyMainChainDefault
):
    pass


class HttpTablesTestEmptyChainReplyH2(H2Config, test_http_tables.HttpTablesTestEmptyChainReply):
    pass


class HttpTablesTestEmptyChainDropH2(H2Config, test_http_tables.HttpTablesTestEmptyChainDrop):
    pass


class HttpTablesTestEmptyChainDefaultH2(H2Config, test_http_tables.HttpTablesTestEmptyChainDefault):
    pass


class HttpTablesTestMixedChainReplyH2(H2Config, test_http_tables.HttpTablesTestMixedChainReply):
    pass


class HttpTablesTestMixedChainDropH2(H2Config, test_http_tables.HttpTablesTestMixedChainDrop):
    pass


class HttpTablesTestMixedChainDefaultH2(H2Config, test_http_tables.HttpTablesTestMixedChainDefault):
    pass


class HttpTablesTestMixedChainRespH2(H2Config, test_http_tables.HttpTablesTestMixedChainResp):
    requests = [
        (":path", "/static"),
        (":scheme", "https"),
        (":method", "POST"),
        ("host", "tempesta-tech.com"),
    ]


class HttpTablesTestCustomRedirectCorrectVariablesAuthorityH2(
    H2Config, test_http_tables.HttpTablesTestCustomRedirectCorrectVariables
):
    requests = [
        (":authority", test_http_tables.HttpTablesTestCustomRedirectCorrectVariables.host),
        (":path", test_http_tables.HttpTablesTestCustomRedirectCorrectVariables.request_uri),
        (":scheme", "https"),
        (":method", "GET"),
    ]


class HttpTablesTestCustomRedirectCorrectVariablesHostH2(
    H2Config, test_http_tables.HttpTablesTestCustomRedirectCorrectVariables
):
    requests = [
        (":path", test_http_tables.HttpTablesTestCustomRedirectCorrectVariables.request_uri),
        (":scheme", "https"),
        (":method", "GET"),
        ("host", test_http_tables.HttpTablesTestCustomRedirectCorrectVariables.host),
    ]


class HttpTablesTestCustomRedirectNonExistentVariablesH2(
    H2Config, test_http_tables.HttpTablesTestCustomRedirectNonExistentVariables
):
    requests = [
        (":path", test_http_tables.HttpTablesTestCustomRedirectNonExistentVariables.request_uri),
        (":scheme", "https"),
        (":method", "GET"),
        ("host", test_http_tables.HttpTablesTestCustomRedirectNonExistentVariables.host),
    ]


class HttpTablesTestCustomRedirectDifferentResponseStatusH2(
    H2Config, test_http_tables.HttpTablesTestCustomRedirectDifferentResponseStatus
):
    requests = [
        (":path", test_http_tables.HttpTablesTestCustomRedirectDifferentResponseStatus.request_uri),
        (":scheme", "https"),
        (":method", "GET"),
        ("host", test_http_tables.HttpTablesTestCustomRedirectDifferentResponseStatus.host),
    ]


class H2Redirects(tester.TempestaTest):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        }
    ]

    backends = [
        {
            "id": "0",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        }
    ]

    tempesta = {
        "config": """
        listen 443 proto=h2;
        tls_match_any_server_name;

        srv_group default {
            server ${server_ip}:8000;
        }

        vhost tempesta-tech.com {
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            proxy_pass default;
        }

        http_chain redirection_chain {
            uri == "/moved-permanently" -> 301 = /new-location-301;
            uri == "/temporary-redirect" -> 307 = /new-location-307;
            -> tempesta-tech.com;
        }

        http_chain {
            host == "tempesta-tech.com" -> redirection_chain;
        }

        """
    }

    params = [
        ("/moved-permanently", "301", "/new-location-301"),
        ("/temporary-redirect", "307", "/new-location-307"),
    ]

    def test(self):
        self.start_all_services()

        for uri, status, location in self.params:
            request = [
                (":authority", "tempesta-tech.com"),
                (":path", uri),
                (":scheme", "https"),
                (":method", "GET"),
            ]

            client = self.get_client("deproxy")
            client.send_request(request, status)
            self.assertEqual(client.last_response.headers["location"], location)


class HttpTablesTestMarkRuleH2(test_http_tables.HttpTablesTestMarkRule):
    clients = [
        {
            "id": 0,
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
            "ssl_hostname": "tempesta-tech.com",
        }
    ]
