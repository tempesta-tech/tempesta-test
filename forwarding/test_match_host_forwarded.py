"""
Tests for verifying correctness of matching
all host headers (URI, Host, Forwarded).
"""
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
        vhost shop {
        proxy_pass grp1;
        }
        vhost wiki {
        proxy_pass grp2;
        }
        vhost app {
        proxy_pass grp3;
        }
        http_chain {
        hdr host == "testapp.com" -> app;
        hdr forwarded == "host=testshop.com" -> shop;
        host == "badhost.com" -> block;
        host == "testshop.com" -> shop;
        host == "testwiki.com" -> wiki;
        host == "testapp.com" -> app;
        host == [fd80::1cb2:ad12:ca16:98ef]:8080 -> app;
        -> block;
        }
        """
    }

    requests_opt = [
        {
            "uri": "http://testshop.com",  # <--must be matched by "host eq"
            "headers": [("Host", "testwiki.com"), ("Forwarded", "host=testapp.com")],
            "block": False,
            "sid": 0,
        },
        {
            "uri": "http://testshop.com",  # <--must be matched by "host eq"
            "headers": [("Host", "badhost.com"), ("Forwarded", "host=badhost.com")],
            "block": False,
            "sid": 0,
        },
        {
            "uri": "http://testshop.com",
            "headers": [
                ("Host", "testapp.com"),  # <--must be matched by "hdr host == testapp.com"
                ("Forwarded", "host=testwiki.com"),
            ],
            "block": False,
            "sid": 2,
        },
        {
            "uri": "http://badhost.com",
            "headers": [
                ("Host", "badhost.com"),
                ("Forwarded", "host=testshop.com"),  # <--must be matched by "hdr forwarded"
            ],
            "block": False,
            "sid": 0,
        },
        {
            "uri": "http://badhost.com",
            "headers": [
                ("Host", "badhost.com"),
                ("Forwarded", "host=unkhost.com"),
                ("Forwarded", "host=testshop.com"),  # <--must be matched by "hdr forwarded"
            ],
            "block": False,
            "sid": 0,
        },
        {
            "uri": "/foo",
            "headers": [
                ("Host", "testwiki.com"),  # <--must be matched by "host eq"
                ("Forwarded", "host=testapp.com"),
            ],
            "block": False,
            "sid": 1,
        },
        {
            "uri": "/foo",
            "headers": [
                ("Host", "unkhost.com"),
                ("Forwarded", "host=testapp.com"),  # <--must be matched by "host eq"
            ],
            "block": False,
            "sid": 2,
        },
        {
            "uri": "/foo",
            "headers": [
                ("Host", "unkhost.com"),
                ("Forwarded", "HoSt=TesTaPp.cOm"),  # <--must be matched by "host eq"
            ],
            "block": False,
            "sid": 2,
        },
        {
            "uri": "/foo",
            "headers": [
                ("Host", "unkhost.com"),
                (
                    "Forwarded",
                    'host="[fd80::1cb2:ad12:ca16:98ef]:8080"',
                ),  # <--must be matched by "host eq"
            ],
            "block": False,
            "sid": 2,
        },
        {
            "uri": "/foo",
            "headers": [("Host", "badhost.com"), ("Forwarded", "host=testapp.com")],
            "block": True,
            "sid": 0,
        },
        {"uri": "/foo", "headers": [("Host", "unkhost.com")], "block": True, "sid": 0},
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
        Send requests with different hosts
        and check correctness of forwarding
        by compare last request on client and
        server.
        """
        self.start_all()
        count = len(self.chains)
        for i in range(count):
            sid = self.requests_opt[i]["sid"]
            self.process(self.get_client(i), self.get_server(sid), self.chains[i])


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
