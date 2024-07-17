"""
Tests for verifying correctness of matching
all host headers (URI, Host, Forwarded).
"""
import time

from framework import deproxy_client, tester
from helpers import chains
from framework.parameterize import param, parameterize, parameterize_class

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

class regex_matcher(tester.TempestaTest):
    backends = [
    ]

    tempesta = {
    }

    requests_opt = [
    ]

    blocked_response_status = "403"
    success_response_status = "200"
    chains = []

    def add_client(self, cid):
        class_name = type(self).__name__
        if class_name.find("Http") != -1:
            client = {"id": cid, "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"}
        else:
            client = {"id": cid, "type": "deproxy_h2", "addr": "${tempesta_ip}", "port": "443", "ssl": True}
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

    def process(self, client, chain, request, sid):
        if isinstance(client, deproxy_client.DeproxyClientH2):
            client.make_request(request["h2_headers"]) 
        else:
            client.make_request(chain.request.msg)      
            
        client.wait_for_response()
        if chain.fwd_request:
            last_response_status = client.last_response.status    
            self.assertEqual(self.success_response_status, last_response_status)
            last_body = client.last_response.body
            self.assertEqual(str(sid), last_body)
        else:
            last_response_status = client.last_response.status
            self.assertEqual(self.blocked_response_status, last_response_status)

    def test_chains(self):
        """
        Send requests with different URI and headers
        and check correctness of forwarding
        by compare last response body with sid of
        whaiting server.
        """
        self.start_all()
        count = len(self.chains)
        for i in range(count):
            sid = self.requests_opt[i]["sid"]
            client = self.get_client(i)
            self.process(client, self.chains[i], self.requests_opt[i], sid)


@parameterize_class(
    [
        {"name": "Http"},
        {"name": "H2"},
    ]
)
class TestMatchLocations(regex_matcher):

    backends = [
        {
            "id": 0,
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 1\r\n\r\n0",
        },
        {
            "id": 1,
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 1\r\n\r\n1",
        },
        {
            "id": 2,
            "type": "deproxy",
            "port": "8002",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 1\r\n\r\n2",
        },
        {
            "id": 3,
            "type": "deproxy",
            "port": "8003",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 1\r\n\r\n3",
        },
        {
            "id": 4,
            "type": "deproxy",
            "port": "8004",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 1\r\n\r\n4",
        },
    ]

    tempesta = {
        "config": """

        listen 80;
        listen 443 proto=h2;
        
        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;
        access_log on;

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
            "uri": "/testwiki", # <--The second must be matched by "location ~ "/wiki/"" of vhost test.
            "headers": [("Host", "testwiki.com"),], # <--The first must be matched by "host ~* "/test/" -> test".
            "h2_headers": [
                (":authority", "testwiki.com"), # <--The first must be matched by "host ~* "/test/" -> test".
                (":path", "/testwiki"), # <--The second must be matched by "location ~ "/wiki/"" of vhost test.
                (":scheme", "https"),
                (":method", "GET"),
            ],
            "block": False,
            "sid": 1,
        },
        {
            "uri": "/testshop", # <--The second must be matched by "location ~ "/shop/"" of vhost test.
            "headers": [
                ("Host", "testapp.com"), # <--The first must be matched by "host ~* "/test/" -> test".
            ],
            "h2_headers": [
                (":authority", "testapp.com"), # <--The first must be matched by "host ~* "/test/" -> test".
                (":path", "/testshop"), # <--The second must be matched by "location ~ "/shop/"" of vhost test.
                (":scheme", "https"),
                (":method", "GET"),
            ],
            "block": False,
            "sid": 0,
        },
        {
            "uri": "/testapp",  # <--The second is not matched with anything.
            "headers": [("Host", "testapp.com"),], #<--The first must be matched by "host ~* "/test/" -> test".
            "h2_headers": [
                (":authority", "testapp.com"), #<--The first must be matched by "host ~* "/test/" -> test".
                (":path", "/testapp"), # <--The second is not matched with anything.
                (":scheme", "https"),
                (":method", "GET"),
            ],
            "block": False,
            "sid": 4,
        },

        {
            "uri": "/testwiki", # <--The second must be matched by "location ~ "/wiki/"" of vhost work.
            "headers": [
                ("Host", "WorkShop.com"), # <--The first must be matched by "host ~* "/work/" -> work".
            ],
            "h2_headers": [
                (":authority", "WorkShop.com"), # <--The first must be matched by "host ~* "/work/" -> work".
                (":path", "/testwiki"), # <--The second must be matched by "location ~ "/wiki/"" of vhost work.
                (":scheme", "https"),
                (":method", "GET"),
            ],
            "block": False,
            "sid": 3,
        },
        {
            "uri": "/testshop", # <--The second must be matched by "location ~ "/shop/"" of vhost work.
            "headers": [
                ("Host", "WorkWiki.com"), # <--The first must be matched by "host ~* "/work/" -> work".
            ],
            "h2_headers": [
                (":authority", "WorkWiki.com"), # <--The first must be matched by "host ~* "/work/" -> work".
                (":path", "/testshop"), # <--The second must be matched by "location ~ "/shop/"" of vhost work.
                (":scheme", "https"),
                (":method", "GET"),
            ],
            "block": False,
            "sid": 2,
        },
        {
            "uri": "/testapp",  # <--The second is not matched with anything.
            "headers": [("Host", "workapp.com"),], # <--The first must be matched by "host ~* "/work/" -> work".
            "h2_headers": [
                (":authority", "workapp.com"),# <--The first must be matched by "host ~* "/work/" -> work".
                (":path", "/testapp"),# <--The second is not matched with anything.
                (":scheme", "https"),
                (":method", "GET"),
            ],
            "block": False,
            "sid": 4,
        },
        {
            "uri": "/ignored",
            "headers": [
                ("Host", "ordinary.com"), # <--Must fail all matches and be blocked.
            ],
            "h2_headers": [
                (":authority", "ordinary.com"), # <--Must fail all matches and be blocked.
                (":path", "/ignored"),
                (":scheme", "https"),
                (":method", "GET"),
            ],
            "block": True,
            "sid": 0,
        },
    ]


@parameterize_class(
    [
        {"name": "Http"},
        {"name": "H2"},
    ]
)
class TestMatchHost(regex_matcher):
    backends = [
        {
            "id": 0,
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 1\r\n\r\n0",
        },
        {
            "id": 1,
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 1\r\n\r\n1",
        },
        {
            "id": 2,
            "type": "deproxy",
            "port": "8002",
            "response": "static",
           "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 1\r\n\r\n2",
        },
        {
            "id": 3,
            "type": "deproxy",
            "port": "8003",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 1\r\n\r\n3",
        },
    ]

    tempesta = {
        "config": """

        listen 80;
        listen 443 proto=h2;
        
        tls_certificate ${tempesta_workdir}/tempesta.crt;
        tls_certificate_key ${tempesta_workdir}/tempesta.key;
        tls_match_any_server_name;
        access_log on;

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
        hdr host ~ "/stap/" -> app;
        host ~* "/dho/" -> block;
        host ~ "/tsho/" -> shop;
        hdr host ~ "/wiki/" -> wiki;
        hdr forwarded ~ "/t=se/" -> doc;
        hdr forwarded ~ "/host\./" -> app;
        host ~* "/app|ad12:ca16/" -> app; 
        -> block;
        }
        """
    }

    requests_opt = [
        {            
            "uri": "http://testshop.com",  # <--Must be matched by "host ~ "/tsho/"".
            "headers": [
                ("Host", "testshop.com"), 
                ("Forwarded", "host=testapp.com"),
            ],
            "h2_headers": [
                (":authority", "testshop.com"),# <--Must be matched by "host ~ "/tsho/"".
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
            ],
            "block": False,
            "sid": 0,
        },
        {
            "uri": "http://testshop.com",
            "headers": [
                ("Host", "testapp.com"),  # <--Must be matched by "hdr host ~ "/stap/"".
            ],
            "h2_headers": [
                (":authority", "testapp.com"),# <--Must be matched by "hdr host ~ "/stap/"".
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
            ],
            "block": False,
            "sid": 2,
        },
        {
            "uri": "http://bobhost.com", # <--Must be blocked.
            "headers": [
                ("Host", "badshop.com"),  
            ],
            "h2_headers": [
                (":authority", "bobhost.com"),# <--Must be blocked.
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
            ],
            "block": True,
            "sid": 0,
        },
        {
            "uri": "/foo",
            "headers": [
                ("Host", "testwiki.com"), # <--Must be matched by "hdr host ~ "/wiki/".
            ],
            "h2_headers": [
                (":authority", "testwiki.com"),
                (":path", "/foo"),
                (":scheme", "https"),
                (":method", "GET"),
                ("Host", "testwiki.com") # <--Must be matched by "hdr host ~ "/wiki/".
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
            "h2_headers": [
                (":authority", "TesTaPp.cOm"),
                (":path", "/foo"),
                (":scheme", "https"),
                (":method", "GET"),
                ("Forwarded", "host=sent.hhh.ignored"),# <--Must be matched by "hdr forwarded ~ "/t=se/"".
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
            "h2_headers": [
                (":authority", "TesTaPp.cOm"),
                (":path", "/foo"),
                (":scheme", "https"),
                (":method", "GET"),
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
            "h2_headers": [
                (":authority", "TesTaPp.cOm"),
                (":path", "/foo"), 
                (":scheme", "https"),
                (":method", "GET"),
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
                ("Forwarded","host=forwarded.hhh.ignored"),  
            ],
            "h2_headers": [
                (":authority", "[fd80::1cb2:ad12:ca16:98ef]:8080"),
                (":path", "/foo"),
                (":scheme", "https"),
                (":method", "GET"),
                ("Host", "[fd80::1cb2:ad12:ca16:98ef]:8080"), # <--Must be matched by "host ~* "/app|ad12:ca16/"".
                ("Forwarded","host=forwarded.hhh.ignored"),
            ],
            "block": False,
            "sid": 2,
        },
        {
            "uri": "/foo", # <--must be blocked
            "headers": [("Host", "badhost.com"), ("Forwarded", "host=forwarded.host.ignored")],
            "h2_headers": [
                (":authority", "badhost.com"),
                (":path", "/foo"),
                (":scheme", "https"),
                (":method", "GET"),
                ("Host", "badhost.com"), 
                ("Forwarded", "host=forwarded.host.ignored"),
            ],
            "block": True,
            "sid": 0,
        },
        {
            "uri": "/foo", # <--must be blocked
            "headers": [("Host", "unkhost.com")],
            "h2_headers": [
                (":authority", "unkhost.com"),
                (":path", "/foo"),
                (":scheme", "https"),
                (":method", "GET"),
                ("Host", "unkhost.com"),
            ],
            "block": True, 
            "sid": 0},
    ]