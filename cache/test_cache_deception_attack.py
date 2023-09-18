"""Functional tests for cache deception attack."""

# Web Cache Deception Attack
#
# An attacker who lures a logged-on user to access
# http://www.example.com/home.php/picts/bear.jpg will cause this page -
# containing the user's personal content - to be cached and thus
# publicly-accessible.
# Tempesta FW must not disregard Cache-Control header, regardless
# configuration of caching by URI resource suffix.
#
# https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html


__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework import tester
from helpers import tf_cfg

RESPONSE_CC_NO_STORE = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nCache-Control: no-store\r\n\r\n"

RESPONSE_CC_NO_CACHE = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nCache-Control: no-cache\r\n\r\n"

RESPONSE_CC_PRIVATE = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nCache-Control: private\r\n\r\n"

RESPONSE_WITHOUT_CC = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

RESPONSE_PRAGMA_NO_CACHE = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nPragma: no-cache\r\n\r\n"


class TestCacheDeceptionAttackH2(tester.TempestaTest):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        }
    ]

    tempesta = {
        "config": """
listen 80;
listen 443 proto=h2;

server ${server_ip}:8000;

vhost default {
    proxy_pass default;
    tls_certificate ${tempesta_workdir}/tempesta.crt;
    tls_certificate_key ${tempesta_workdir}/tempesta.key;
    tls_match_any_server_name;
}

cache_fulfill suffix ".jpg";
"""
    }

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "",
        },
    ]

    def base_scenario(self, cache_lvl: int, response: str, request: list):
        """
        Send each request twice and assert that backend server also receives
        exactly two requests
        """
        tempesta = self.get_tempesta()
        tempesta.config.defconfig += f"cache {cache_lvl};"

        server = self.get_server("deproxy")
        server.set_response(response)

        self.start_all_services()

        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.send_request(request, "200")
        deproxy_cl.send_request(request, "200")

        self.assertEqual(2, len(server.requests))

    def test_cc_no_store_in_response_and_cache_lvl_1(self):
        self.base_scenario(
            cache_lvl=1,
            response=RESPONSE_CC_NO_STORE,
            request=self.get_client("deproxy").create_request(
                method="GET", headers=[], uri="/home.php/picts/bear.jpg"
            ),
        )

    def test_cc_no_store_in_response_and_cache_lvl_2(self):
        self.base_scenario(
            cache_lvl=2,
            response=RESPONSE_CC_NO_STORE,
            request=self.get_client("deproxy").create_request(
                method="GET", headers=[], uri="/home.php/picts/bear.jpg"
            ),
        )

    def test_cc_no_cache_in_response_and_cache_lvl_1(self):
        self.base_scenario(
            cache_lvl=1,
            response=RESPONSE_CC_NO_CACHE,
            request=self.get_client("deproxy").create_request(
                method="GET", headers=[], uri="/home.php/picts/bear.jpg"
            ),
        )

    def test_cc_no_cache_in_response_and_cache_lvl_2(self):
        self.base_scenario(
            cache_lvl=2,
            response=RESPONSE_CC_NO_CACHE,
            request=self.get_client("deproxy").create_request(
                method="GET", headers=[], uri="/home.php/picts/bear.jpg"
            ),
        )

    def test_cc_private_in_response_and_cache_lvl_1(self):
        self.base_scenario(
            cache_lvl=1,
            response=RESPONSE_CC_PRIVATE,
            request=self.get_client("deproxy").create_request(
                method="GET", headers=[], uri="/home.php/picts/bear.jpg"
            ),
        )

    def test_cc_private_in_response_and_cache_lvl_2(self):
        self.base_scenario(
            cache_lvl=2,
            response=RESPONSE_CC_PRIVATE,
            request=self.get_client("deproxy").create_request(
                method="GET", headers=[], uri="/home.php/picts/bear.jpg"
            ),
        )

    def test_cc_no_store_in_request_and_cache_lvl_1(self):
        self.base_scenario(
            cache_lvl=1,
            response=RESPONSE_WITHOUT_CC,
            request=self.get_client("deproxy").create_request(
                method="GET",
                headers=[("cache-control", "no-store")],
                uri="/home.php/picts/bear.jpg",
            ),
        )

    def test_cc_no_store_in_request_and_cache_lvl_2(self):
        self.base_scenario(
            cache_lvl=2,
            response=RESPONSE_WITHOUT_CC,
            request=self.get_client("deproxy").create_request(
                method="GET",
                headers=[("cache-control", "no-store")],
                uri="/home.php/picts/bear.jpg",
            ),
        )

    def test_cc_no_cache_in_request_and_cache_lvl_1(self):
        self.base_scenario(
            cache_lvl=1,
            response=RESPONSE_WITHOUT_CC,
            request=self.get_client("deproxy").create_request(
                method="GET",
                headers=[("cache-control", "no-cache")],
                uri="/home.php/picts/bear.jpg",
            ),
        )

    def test_cc_no_cache_in_request_and_cache_lvl_2(self):
        self.base_scenario(
            cache_lvl=2,
            response=RESPONSE_WITHOUT_CC,
            request=self.get_client("deproxy").create_request(
                method="GET",
                headers=[("cache-control", "no-cache")],
                uri="/home.php/picts/bear.jpg",
            ),
        )

    def test_pragma_no_cache_in_request_and_cache_lvl_1(self):
        self.base_scenario(
            cache_lvl=1,
            response=RESPONSE_WITHOUT_CC,
            request=self.get_client("deproxy").create_request(
                method="GET", headers=[("pragma", "no-cache")], uri="/home.php/picts/bear.jpg"
            ),
        )

    def test_pragma_no_cache_in_request_and_cache_lvl_2(self):
        self.base_scenario(
            cache_lvl=2,
            response=RESPONSE_WITHOUT_CC,
            request=self.get_client("deproxy").create_request(
                method="GET", headers=[("pragma", "no-cache")], uri="/home.php/picts/bear.jpg"
            ),
        )

    def test_pragma_no_cache_in_response_and_cache_lvl_1(self):
        self.base_scenario(
            cache_lvl=1,
            response=RESPONSE_PRAGMA_NO_CACHE,
            request=self.get_client("deproxy").create_request(
                method="GET", headers=[], uri="/home.php/picts/bear.jpg"
            ),
        )

    def test_pragma_no_cache_in_response_and_cache_lvl_2(self):
        self.base_scenario(
            cache_lvl=2,
            response=RESPONSE_PRAGMA_NO_CACHE,
            request=self.get_client("deproxy").create_request(
                method="GET", headers=[], uri="/home.php/picts/bear.jpg"
            ),
        )


class TestCacheDeceptionAttack(TestCacheDeceptionAttackH2):
    clients = [
        {"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"},
    ]
