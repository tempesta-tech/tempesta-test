"""
Tests for verifying correctness of matching
all host headers (URI, Host, Forwarded).
"""
import time

from framework import tester
from helpers import chains

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestMatchHost(tester.TempestaTest):

    backends = [
        {
            "id": 0,
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        },
        {
            "id": 1,
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        },
        {
            "id": 2,
            "type": "deproxy",
            "port": "8002",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        },
        {
            "id": 3,
            "type": "deproxy",
            "port": "8003",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        },
    ]

    tempesta = {
        "config": """
        block_action attack reply;
        srv_group grp1 {
        server ${server_ip}:8000;
        }
        srv_group grp2 {
        server ${server_ip}:8001;
        }
        srv_group grp3 {
        server ${server_ip}:8002;
        }
        srv_group grp4 {
        server ${server_ip}:8003;
        }
        vhost shop {
        proxy_pass grp1;
        }
        vhost wiki {
        proxy_pass grp2;
        }
        vhost app {
        proxy_pass grp3;
        }
        vhost doc {
        proxy_pass grp4;
        }
        http_chain {
        hdr host ~ "/stap/" -> app; #testapp.com
        host ~* "/dho/" -> block; #badhost.com
        host ~ "/tsho/" -> shop; #testshop.com;
        hdr host ~ "/wiki/" -> wiki; #testwiki.com;
        hdr forwarded ~ "/t=se/" -> doc;
        hdr forwarded ~ "/host\./" -> app;
        host ~* "/app|ad12:ca16/" -> app; #[fd80::1cb2:ad12:ca16:98ef] or testapp.com
        -> block;
        }
        """
    }

    requests_opt = [
        {
            "uri": "http://testshop.com",  # <--Must be matched by "host ~ "/tsho/"".
            "headers": [("Host", "testwiki.com"), ("Forwarded", "host=testapp.com")],
            "block": False,
            "sid": 0,
        },
        {
            "uri": "http://testshop.com",  # <--Must be matched by "host ~ "/tsho/"".
            "headers": [("Host", "badhost.com"), ("Forwarded", "host=badhost.com")],
            "block": False,
            "sid": 0,
        },
        {
            "uri": "http://testshop.com",
            "headers": [
                ("Host", "testapp.com"),  # <--Must be matched by "hdr host ~ "/stap/"".
            ],
            "block": False,
            "sid": 2,
        },
        {
            "uri": "http://bobhost.com", # <--Must be blocked.
            "headers": [
                ("Host", "badshop.com"),  
            ],
            "block": True,
            "sid": 0,
        },
        {
            "uri": "/foo",
            "headers": [
                ("Host", "testwiki.com"), # <--Must be matched by "hdr host ~ "/wiki/".
            ],
            "block": False,
            "sid": 1,
        },
         {
            "uri": "/foo",
            "headers": [
                ("Host", "TesTaPp.cOm"), 
                ("Forwarded", "host=sent.hhh.ignored"), # <--Must be matched by "hdr forwarded ~ "/t=se/"".
            ],
            "block": False,
            "sid": 3,
        },
         {
            "uri": "/foo",
            "headers": [
                ("Host", "TesTaPp.cOm"), 
                ("Forwarded", "host=forwarded.host.ignored"), # <--Must be matched by "hdr forwarded ~ "/host./"".
            ],
            "block": False,
            "sid": 2,
        },
        {
            "uri": "/foo",
            "headers": [
                ("Host", "TesTaPp.cOm"), # <--Must be matched by "host ~* "/app|ad12:ca16/"".
                ("Forwarded", "host=forwarded.hhh.ignored"),
            ],
            "block": False,
            "sid": 2,
        },
        {
            "uri": "/foo",
            "headers": [
                ("Host", "[fd80::1cb2:ad12:ca16:98ef]:8080"), # <--Must be matched by "host ~* "/app|ad12:ca16/"".
                (
                    "Forwarded","host=forwarded.hhh.ignored",
                ),  
            ],
            "block": False,
            "sid": 2,
        },
        {
            "uri": "/foo", # <--must be blocked
            "headers": [("Host", "badhost.com"), ("Forwarded", "host=forwarded.host.ignored")],
            "block": True,
            "sid": 0,
        },
        {
            "uri": "/foo", # <--must be blocked
            "headers": [("Host", "unkhost.com")], 
            "block": True, 
            "sid": 0},
    ]

    blocked_response_status = "403"
    chains = []

    def add_client(self, cid):
        client = {"id": cid, "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"}
        self.clients.append(client)

    def init_chain(self, req_opt):
        ch = chains.base(uri=req_opt["uri"])
        if req_opt["block"]:
            for header, value in req_opt["headers"]:
                ch.request.headers.delete_all(header)
                ch.request.headers.add(header, value)
                ch.request.update()
                ch.fwd_request = None
        else:
            for request in [ch.request, ch.fwd_request]:
                for header, value in req_opt["headers"]:
                    request.headers.delete_all(header)
                    request.headers.add(header, value)
                    request.update()
        self.chains.append(ch)

    def setUp(self):
        del self.chains[:]
        count = len(self.requests_opt)
        for i in range(count):
            self.init_chain(self.requests_opt[i])
            self.add_client(i)
        tester.TempestaTest.setUp(self)

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        time.sleep(2) #It is necessary to wait until regexes are compiled
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections())

    def process(self, client, server, chain):
        client.make_request(chain.request.msg)
        client.wait_for_response()

        if chain.fwd_request:
            chain.fwd_request.set_expected()
            self.assertEqual(server.last_request, chain.fwd_request)
        else:
            last_response_status = client.last_response.status
            self.assertEqual(self.blocked_response_status, last_response_status)

    def test_chains(self):
        """
        Send requests with different URI and headers
        and check correctness of forwarding
        by compare last request on client and
        server.
        """
        self.start_all()
        count = len(self.chains)
        for i in range(count):
            sid = self.requests_opt[i]["sid"]
            self.process(self.get_client(i), self.get_server(sid), self.chains[i])


class TestMatchLocations(tester.TempestaTest):

    backends = [
        {
            "id": 0,
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        },
        {
            "id": 1,
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        },
        {
            "id": 2,
            "type": "deproxy",
            "port": "8002",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        },
        {
            "id": 3,
            "type": "deproxy",
            "port": "8003",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        },
        {
            "id": 4,
            "type": "deproxy",
            "port": "8004",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        },
    ]

    tempesta = {
        "config": """
        block_action attack reply;
        srv_group grp1 {
        server ${server_ip}:8000;
        }
        srv_group grp2 {
        server ${server_ip}:8001;
        }
        srv_group grp3 {
        server ${server_ip}:8002;
        }
        srv_group grp4 {
        server ${server_ip}:8003;
        }
        srv_group grp5 {
        server ${server_ip}:8004;
        }

        vhost test {
            proxy_pass grp5;
            location ~ "/shop/" {
            proxy_pass grp1;
            }
            location ~ "/wiki/" {
            proxy_pass grp2;
            }
        }

        vhost work {
            proxy_pass grp5;
            location ~* "/shop/" {
            proxy_pass grp3;
            }
            location ~ "/wiki/" {
            proxy_pass grp4;
            }
        }

        http_chain {
            host ~* "/test/" -> test;
            host ~* "/work/" -> work;
            -> block;
        }
        """
    }

    requests_opt = [
        {
            "uri": "/testwiki",  # <--The second must be matched by "location ~ "/wiki/"" of vhost test.
            "headers": [("Host", "testwiki.com"),],# <--The first must be matched by "host ~* "/test/" -> test".
            "block": False,
            "sid": 1,
        },
        {
            "uri": "/testshop", # <--The second must be matched by "location ~ "/shop/"" of vhost test.
            "headers": [
                ("Host", "testapp.com"),  # <--The first must be matched by "host ~* "/test/" -> test".
            ],
            "block": False,
            "sid": 0,
        },
        {
            "uri": "/testapp",  # <--The second is not matched with anything.
            "headers": [("Host", "testapp.com"),],#<--The first must be matched by "host ~* "/test/" -> test".
            "block": False,
            "sid": 4,
        },

        {
            "uri": "/testwiki",# <--The second must be matched by "location ~ "/wiki/"" of vhost work.
            "headers": [
                ("Host", "WorkShop.com"), # <--The first must be matched by "host ~* "/work/" -> work".
            ],
            "block": False,
            "sid": 3,
        },
        {
            "uri": "/testshop", # <--The second must be matched by "location ~ "/shop/"" of vhost work.
            "headers": [
                ("Host", "WorkWiki.com"), # <--The first must be matched by "host ~* "/work/" -> work".
            ],
            "block": False,
            "sid": 2,
        },
        {
            "uri": "/testapp",  # <--The second is not matched with anything.
            "headers": [("Host", "workapp.com"),], # <--The first must be matched by "host ~* "/work/" -> work".
            "block": False,
            "sid": 4,
        },


        {
            "uri": "/ignored",
            "headers": [
                ("Host", "ordinary.com"), # <--Must fail all matches and be blocked.
            ],
            "block": True,
            "sid": 0,
        },
    ]

    blocked_response_status = "403"
    chains = []

    def add_client(self, cid):
        client = {"id": cid, "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"}
        self.clients.append(client)

    def init_chain(self, req_opt):
        ch = chains.base(uri=req_opt["uri"])
        if req_opt["block"]:
            for header, value in req_opt["headers"]:
                ch.request.headers.delete_all(header)
                ch.request.headers.add(header, value)
                ch.request.update()
                ch.fwd_request = None
        else:
            for request in [ch.request, ch.fwd_request]:
                for header, value in req_opt["headers"]:
                    request.headers.delete_all(header)
                    request.headers.add(header, value)
                    request.update()
        self.chains.append(ch)

    def setUp(self):
        del self.chains[:]
        count = len(self.requests_opt)
        for i in range(count):
            self.init_chain(self.requests_opt[i])
            self.add_client(i)
        tester.TempestaTest.setUp(self)

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        time.sleep(2) #It is necessary to wait until regexes are compiled
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections())

    def process(self, client, server, chain):
        client.make_request(chain.request.msg)
        client.wait_for_response()

        if chain.fwd_request:
            chain.fwd_request.set_expected()
            self.assertEqual(server.last_request, chain.fwd_request)
        else:
            last_response_status = client.last_response.status
            self.assertEqual(self.blocked_response_status, last_response_status)

    def test_locations(self):
        """
        Send requests with different hosts and locaations
        and check correctness of forwarding
        by compare last request on client and
        server.
        """
        self.start_all()
        count = len(self.chains)
        for i in range(count):
            sid = self.requests_opt[i]["sid"]
            self.process(self.get_client(i), self.get_server(sid), self.chains[i])

