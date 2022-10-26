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

import os

from framework import deproxy_server, tester
from framework.templates import fill_template
from helpers import control, deproxy, tempesta, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TempestaCacheSharding(tester.TempestaTest):

    tempesta = {
        "config": """
server ${general_ip}:8000;

cache 1;
cache_fulfill suffix ".jpg";
""",
    }


class TestCacheReplicated(tester.TempestaTest):

    tempesta = {
        "config": """
server ${general_ip}:8000;

cache 2;
cache_fulfill suffix ".jpg";
""",
    }


class NoStoreBackends(tester.TempestaTest):

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": """HTTP/1.1 200 OK
Content-Length: 0
Cache-Control: no-store

""",
        },
    ]


class NoCacheBackends(tester.TempestaTest):

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": """HTTP/1.1 200 OK
Content-Length: 0
Cache-Control: no-cache

""",
        },
    ]


class CachePrivateBackends(tester.TempestaTest):

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": """HTTP/1.1 200 OK
Content-Length: 0
Cache-Control: private

""",
        },
    ]


class PragmaNoCacheBackends(tester.TempestaTest):

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": """HTTP/1.1 200 OK
Content-Length: 0
Pragma: no-cache

""",
        },
    ]


class WithoutCacheControlBackends(tester.TempestaTest):

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": """HTTP/1.1 200 OK
Content-Length: 0

""",
        },
    ]


class CacheDeceptionAttackBase(tester.TempestaTest):

    clients = [
        {"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"},
    ]

    # Send each request twice and assert that backend server also receives
    # exactly two requests
    def make_requests(self, request):
        deproxy_srv = self.get_server("deproxy")
        deproxy_srv.start()
        self.assertEqual(0, len(deproxy_srv.requests))
        self.start_tempesta()
        deproxy_cl = self.get_client("deproxy")
        deproxy_cl.start()
        self.deproxy_manager.start()
        self.assertTrue(deproxy_srv.wait_for_connections(timeout=1))
        deproxy_cl.make_request(request)
        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(resp, "Response not received")
        deproxy_cl.make_request(request)
        resp = deproxy_cl.wait_for_response(timeout=5)
        self.assertTrue(resp, "Response not received")
        self.assertEqual(2, len(deproxy_cl.responses))
        self.assertEqual(2, len(deproxy_srv.requests))


class CacheDeceptionAttackTest01(CacheDeceptionAttackBase, TempestaCacheSharding, NoStoreBackends):
    def test(self):
        request = "GET /home.php/picts/bear.jpg HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        self.make_requests(request)


class CacheDeceptionAttackTest02(CacheDeceptionAttackBase, TestCacheReplicated, NoStoreBackends):
    def test(self):
        request = "GET /home.php/picts/bear.jpg HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        self.make_requests(request)


class CacheDeceptionAttackTest03(CacheDeceptionAttackBase, TempestaCacheSharding, NoCacheBackends):
    def test(self):
        request = "GET /home.php/picts/bear.jpg HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        self.make_requests(request)


class CacheDeceptionAttackTest04(CacheDeceptionAttackBase, TestCacheReplicated, NoCacheBackends):
    def test(self):
        request = "GET /home.php/picts/bear.jpg HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        self.make_requests(request)


class CacheDeceptionAttackTest05(
    CacheDeceptionAttackBase, TempestaCacheSharding, CachePrivateBackends
):
    def test(self):
        request = "GET /home.php/picts/bear.jpg HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        self.make_requests(request)


class CacheDeceptionAttackTest06(
    CacheDeceptionAttackBase, TestCacheReplicated, CachePrivateBackends
):
    def test(self):
        request = "GET /home.php/picts/bear.jpg HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        self.make_requests(request)


class CacheDeceptionAttackTest07(
    CacheDeceptionAttackBase, TempestaCacheSharding, WithoutCacheControlBackends
):
    def test(self):
        request = (
            "GET /home.php/picts/bear.jpg HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Cache-Control: no-store\r\n"
            "\r\n"
        )
        self.make_requests(request)


class CacheDeceptionAttackTest08(
    CacheDeceptionAttackBase, TestCacheReplicated, WithoutCacheControlBackends
):
    def test(self):
        request = (
            "GET /home.php/picts/bear.jpg HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Cache-Control: no-store\r\n"
            "\r\n"
        )
        self.make_requests(request)


class CacheDeceptionAttackTest09(
    CacheDeceptionAttackBase, TempestaCacheSharding, WithoutCacheControlBackends
):
    def test(self):
        request = (
            "GET /home.php/picts/bear.jpg HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Cache-Control: no-cache\r\n"
            "\r\n"
        )
        self.make_requests(request)


class CacheDeceptionAttackTest10(
    CacheDeceptionAttackBase, TestCacheReplicated, WithoutCacheControlBackends
):
    def test(self):
        request = (
            "GET /home.php/picts/bear.jpg HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Cache-Control: no-cache\r\n"
            "\r\n"
        )
        self.make_requests(request)


class CacheDeceptionAttackTest11(
    CacheDeceptionAttackBase, TempestaCacheSharding, WithoutCacheControlBackends
):
    def test(self):
        request = (
            "GET /home.php/picts/bear.jpg HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Pragma: no-cache\r\n"
            "\r\n"
        )
        self.make_requests(request)


class CacheDeceptionAttackTest12(
    CacheDeceptionAttackBase, TestCacheReplicated, WithoutCacheControlBackends
):
    def test(self):
        request = (
            "GET /home.php/picts/bear.jpg HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Pragma: no-cache\r\n"
            "\r\n"
        )
        self.make_requests(request)


class CacheDeceptionAttackTest13(
    CacheDeceptionAttackBase, TempestaCacheSharding, PragmaNoCacheBackends
):
    def test(self):
        request = "GET /home.php/picts/bear.jpg HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        self.make_requests(request)


class CacheDeceptionAttackTest14(
    CacheDeceptionAttackBase, TestCacheReplicated, PragmaNoCacheBackends
):
    def test(self):
        request = "GET /home.php/picts/bear.jpg HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        self.make_requests(request)
