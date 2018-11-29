from helpers import control, tempesta, tf_cfg
from testers import stress

from framework import tester

import os
import unittest

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017-2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

pipeline_lua = \
r"""-- example script demonstrating HTTP pipelining

local_init = function(args)
   local r = {}
   r[1] = wrk.format("GET", "/")
   r[2] = wrk.format("GET", "/")
   r[3] = wrk.format("GET", "/")
   r[4] = wrk.format("GET", "/")
   r[5] = wrk.format("GET", "/")
   r[6] = wrk.format("GET", "/")
   r[7] = wrk.format("GET", "/")

   req = table.concat(r)
end

request = function()
   return req
end
"""

lua_real = \
r"""local_init = function(args)
    local r = {}
    r[1] = wrk.format("GET", "/")
    r[2] = wrk.format("GET", "/", {["Accept"] = "text/plain"})
    r[3] = wrk.format("POST", "/", {["Content-Length"]="0"})
    r[4] = wrk.format("POST", "/", {["Content-Type"]="text/plain", ["Content-Length"]="0"})
    r[5] = wrk.format("GET", "/", {["Host"] = ""})
    req = table.concat(r)
end

request = function()
    return req
end
"""

lua_real2 = \
r"""wrk.method="GET"
wrk.path="/get-banana/50379/x25hXoI3ZH2Bkv7h53jFBWLc_banana_20161021_teaser_1_verifiedRent.png/optimize"
wrk.headers = {
    ["Host"] = "avatars.mds.yandex.net",
    ["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
    ["Accept"] = "*/*",
    ["Accept-Language"] = "en-US,en;q=0.5",
    ["Accept-Encoding"] = "gzip, deflate, br",
    ["Referer"] = "https://yandex.ru/",
    ["Connection"] = "keep-alive",
    ["If-Modified-Since"] = "Wed, 20 Sep 2017 15:38:32 GMT",
    ["Cache-Control"] = "max-age=0",
}
"""

lua_real_pipelined = \
r"""local r1 = {
    method="GET",
    path="/",
    headers = {
        ["Connection"] = "keep-alive",
        ["Cache-Control"] = "max-age=0",
        ["Upgrade-Insecure-Requests"] = "1",
        ["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.89 Safari/537.36",
        ["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        ["Accept-Encoding"] = "gzip, deflate",
        ["Accept-Language"] = "en-US,en;q=0.9",
        ["If-None-Match"] = "\"29cd-551189982e76f-gzip\"",
        ["If-Modified-Since"] = "Sun, 04 Jun 2017 01:49:40",
    }
}

local r2 = {
    method="GET",
    path="/",
    headers = {
        ["Host"] = "yandex.ru",
        ["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        ["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ["Accept-Language"] = "en-US,en;q=0.5",
        ["Accept-Encoding"] = "gzip, deflate, br",
        ["Cookie"] = "my=YzYBAQA=; yandexuid=1489696891470411041; _ym_uid=1472643187536716147; i=eOSeyr6gEr//nv7qBvDdsLgh+Kdl+2DakdBZFqXtrsS64n4nDa8PAjgcVvyV7ZwMJ7azBh2JNAxLKLLKgH53Qs6Nrsc=; yp=1521586770.szm.1_00:1920x1080:1920x893#1547045375.old.1#1518101365.ygu.1#1516718966.ysl.1#1518187799.csc.1; mda=0; yandex_gid=2; yabs-frequency=/4/0000000000000000/TtroSCWjGNnAi738BO5YVN9mo2qX/; yc=1515768590.cb.1%3A1; zm=m-white_bender.gen.css-https%3Awww_klVxYSejR7PRTES1DInob9ponr4%3Al; _ym_isad=1",
        ["Connection"] = "keep-alive",
        ["Upgrade-Insecure-Requests"] = "1",
        ["Cache-Control"] = "max-age=0",
    }
}

local r3 = {
    method="GET",
    path="/www/_/i/H/t-h2mCk0raxxffOF6ttcnH40Q.js",
    headers = {
        ["Host"] = "yastatic.net",
        ["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
        ["Accept"] = "*/*",
        ["Accept-Language"] = "en-US,en;q=0.5",
        ["Accept-Encoding"] = "gzip, deflate, br",
        ["Referer"] = "https://yandex.ru/",
        ["Origin"] = "https://yandex.ru",
        ["Connection"] = "keep-alive",
        ["If-Modified-Since"] = "Fri, 29 Dec 2017 12:35:14 GMT",
        ["If-None-Match"] = "\"5a463682-28257\"",
        ["Cache-Control"] = "max-age=0",
    }
}

local req

local_init = function()
    local req1 = wrk.format(r1.method, r1.path, r1.headers)
    local req2 = wrk.format(r2.method, r2.path, r2.headers)
    local req3 = wrk.format(r3.method, r3.path, r3.headers)
    req = table.concat({req1, req2, req3})
end

request = function()
    return req
end
"""


lua_get_post = \
r"""local_init = function(args)
    local r = {}
    r[1] = wrk.format("GET", "/")
    r[2] = wrk.format("GET", "/", {["Accept"] = "text/plain"})
    r[3] = wrk.format("POST", "/", {["Content-Length"]="0"})
    r[4] = wrk.format("POST", "/", {["Content-Type"]="text/plain", ["Content-Length"]="0"})
    r[5] = wrk.format("GET", "/", {["Host"] = ""})
    req = table.concat(r)
end

request = function()
    return req
end"""

lua_head_get = \
r"""local_init = function(args)
        local r = {}
        r[1] = wrk.format("HEAD", "/")
        r[2] = wrk.format("GET", "/")
        req = table.concat(r)
end

request = function()
        return req
end
"""

lua_post_empty = \
r"""wrk.method  = "POST"
wrk.path    = "/watch/722545?wmode=7&page-url=https%3A%2F%2Fyandex.ru%2F&charset=utf-8&ut=noindex&exp=Av2_jXAScxmTDQTZg-q1uMSL6TVqJ0Hn&browser-info=ti%3A10%3Aj%3A1%3As%3A1920x1080x24%3Ask%3A1%3Aadb%3A1%3Afpr%3A345015404801%3Acn%3A1%3Aw%3A1905x893%3Az%3A180%3Ai%3A20180109175039%3Aet%3A1515509440%3Aen%3Autf-8%3Av%3A932%3Ac%3A1%3Ala%3Aen-us%3Apv%3A1%3Als%3A853358265090%3Arqn%3A25%3Arn%3A35146689%3Ahid%3A446114216%3Ads%3A0%2C0%2C167%2C10%2C5%2C0%2C0%2C%2C%2C%2C%2C%2C%3Arqnl%3A1%3Ast%3A1515509440%3Au%3A1472643187536716147%3At%3A%D0%AF%D0%BD%D0%B4%D0%B5%D0%BA%D1%81"
wrk.headers = {
    ["Host"] = "mc.yandex.ru",
    ["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0",
    ["Accept"] = "*/*",
    ["Accept-Language"] = "en-US,en;q=0.5",
    ["Accept-Encoding"] = "gzip, deflate, br",
    ["Referer"] = "https://yandex.ru/",
    ["Content-Type"] = "application/x-www-form-urlencoded",
    ["Content-Length"] = "0",
    ["Origin"] = "https://yandex.ru",
    ["Cookie"] = "my=YzYBAQA=; yandexuid=1489696891470411041; _ym_uid=1472643187536716147; i=eOSeyr6gEr//nv7qBvDdsLgh+Kdl+2DakdBZFqXtrsS64n4nDa8PAjgcVvyV7ZwMJ7azBh2JNAxLKLLKgH53Qs6Nrsc=; yp=1521586770.szm.1_00:1920x1080:1920x893#1547045375.old.1#1518101365.ygu.1#1516718966.ysl.1#1518187799.csc.1; mda=0; yandex_gid=2; yabs-frequency=/4/0000000000000000/TtroSCWjONnAi738BO5YVN9mo2qX/; yabs-sid=1024345561515509366; yc=1515768590.cb.1%3A1; zm=m-white_bender.gen.css-https%3Awww_klVxYSejR7PRTES1DInob9ponr4%3Al; _ym_isad=1",
    ["Connection"] = "keep-alive",
    ["Cache-Control"] = "max-age=0",
}
"""

lua_post_small = \
r"""local body = "some not very long text\n"

wrk.method  = "POST"
wrk.headers = {["Content-Type"]="text/plain",
               ["Content-Length"] = string.len(body),
               ["Host"] = "localhost"}
wrk.body    = body
"""


lua_mixed = \
r"""
-- example script demonstrating HTTP pipelining

local_init = function(args)
   local r = {}
   r[1] = wrk.format("OPTIONS", "/")
   r[2] = wrk.format("GET", "/")
   r[3] = wrk.format("HEAD", "/")
   r[4] = wrk.format("POST", "/")
   r[5] = wrk.format("PUT", "/")
   r[6] = wrk.format("PATCH", "/")
   r[7] = wrk.format("DELETE", "/")
   req = table.concat(r)
end

request = function()
   return req
end
"""



class MixedRequests(tester.TempestaTest):

    backends = [
        {
            'id' : 'nginx',
            'type' : 'nginx',
            'check_ports' : [
                {
                    "ip" : "${server_ip}",
                    "port" : "8000",
                }
            ],
            'status_uri' : 'http://${server_ip}:8000/nginx_status',
            'config' : """
pid ${backend_pid};
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

    # [ debug | info | notice | warn | error | crit | alert | emerg ]
    # Fully disable log errors.
    error_log /dev/null emerg;

    # Disable access log altogether.
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
        }
    ]

    clients = [
        {
            'id' : 'wrk',
            'type' : 'wrk',
            'addr' : "${tempesta_ip}:80",
        },
    ]

    tempesta = {
        'config' : """
cache 0;
server ${server_ip}:8600;

""",
    }

    def routine(self, lua):
        nginx = self.get_server('nginx')
        wrk = self.get_client("wrk")

        wrk.set_script("wrk", lua)

        nginx.start()
        nginx.wait_for_connections(timeout=3)

        self.start_tempesta()

        wrk.start()
        self.wait_while_busy(wrk)
        wrk.stop()
        return wrk

    def test_pipeline(self):
        self.routine(pipeline_lua)

    def test_real(self):
        self.routine(lua_real)

    def test_real2(self):
        self.routine(lua_real2)

    def test_real_pipelined(self):
        self.routine(lua_real_pipelined)

    def test_get_post(self):
        self.routine(lua_get_post)

    def test_head_get(self):
        self.routine(lua_head_get)

    def test_post_empty(self):
        self.routine(lua_post_empty)

    def test_post_small(self):
        self.routine(lua_post_small)

    def test_post_big(self):
        # Too big text to put it here explicitly

        text = "content " * 8192
        lua_post_big = "local body = [[\n" + text + "]]\n\n" \
            "wrk.method  = \"POST\"\n" \
            "wrk.path = \"/\"\n" \
            "wrk.headers = {\n" \
            "   [\"Content-Type\"]=\"text/plain\",\n" \
            "   [\"Content-Length\"]=string.len(body),\n" \
            "   [\"Host\"] = \"localhost\"\n" \
            "}\n" \
            "wrk.body    = body"

        self.routine(lua_post_big)

    def test_mixed(self):
        self.routine(lua_mixed)

    # nginx always send 405 for TRACE
    def test_trace(self):
        lua_trace = \
            "wrk.method = \"TRACE\"\n" \
            "wrk.uri = \"/\"\n"

        nginx = self.get_server('nginx')
        wrk = self.get_client("wrk")

        wrk.set_script("wrk", lua_trace)

        nginx.start()
        nginx.wait_for_connections(timeout=3)

        self.start_tempesta()

        wrk.start()
        self.wait_while_busy(wrk)
        wrk.stop()

        self.assertFalse(wrk.statuses.has_key(200))
        self.assertTrue(wrk.statuses.has_key(405))
        self.assertGreater(wrk.statuses[405], 0)

    def test_connect(self):
        lua_connect = \
            "wrk.method = \"CONNECT\"\n" \
            "wrk.uri = \"/\"\n"

        self.routine(lua_connect)
