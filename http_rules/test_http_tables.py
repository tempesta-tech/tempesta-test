"""
Set of tests to verify correctness of requests redirection in HTTP table
(via sereral HTTP chains). Mark rules and match rules are also tested here
(in separate tests).
"""
from helpers import chains, remote
from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2022 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class HttpTablesTest(tester.TempestaTest):

    backends = [
        {
            'id' : 0,
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' :
            'HTTP/1.1 200 OK\r\n'
            'Content-Length: 0\r\n\r\n'
        },
        {
            'id' : 1,
            'type' : 'deproxy',
            'port' : '8001',
            'response' : 'static',
            'response_content' :
            'HTTP/1.1 200 OK\r\n'
            'Content-Length: 0\r\n\r\n'
        },
        {
            'id' : 2,
            'type' : 'deproxy',
            'port' : '8002',
            'response' : 'static',
            'response_content' :
            'HTTP/1.1 200 OK\r\n'
            'Content-Length: 0\r\n\r\n'
        },
        {
            'id' : 3,
            'type' : 'deproxy',
            'port' : '8003',
            'response' : 'static',
            'response_content' :
            'HTTP/1.1 200 OK\r\n'
            'Content-Length: 0\r\n\r\n'
        },
        {
            'id' : 4,
            'type' : 'deproxy',
            'port' : '8004',
            'response' : 'static',
            'response_content' :
            'HTTP/1.1 200 OK\r\n'
            'Content-Length: 0\r\n\r\n'
        },
        {
            'id' : 5,
            'type' : 'deproxy',
            'port' : '8005',
            'response' : 'static',
            'response_content' :
            'HTTP/1.1 200 OK\r\n'
            'Content-Length: 0\r\n\r\n'
        },
        {
            'id' : 6,
            'type' : 'deproxy',
            'port' : '8006',
            'response' : 'static',
            'response_content' :
            'HTTP/1.1 200 OK\r\n'
            'Content-Length: 0\r\n\r\n'
        },
        {
            'id' : 7,
            'type' : 'deproxy',
            'port' : '8007',
            'response' : 'static',
            'response_content' :
            'HTTP/1.1 200 OK\r\n'
            'Content-Length: 0\r\n\r\n'
        }
    ]

    tempesta = {
        'config' :
        """
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
        srv_group grp6 {
        server ${server_ip}:8005;
        }
        srv_group grp7 {
        server ${server_ip}:8006;
        }
        srv_group grp8 {
        server ${server_ip}:8007;
        }
        vhost vh1 {
        proxy_pass grp1;
        }
        vhost vh2 {
        proxy_pass grp2;
        }
        vhost vh3 {
        proxy_pass grp3;
        }
        vhost vh4 {
        proxy_pass grp4;
        }
        vhost vh5 {
        proxy_pass grp5;
        }
        vhost vh6 {
        proxy_pass grp6;
        }
        vhost vh7 {
        proxy_pass grp7;
        }
        vhost vh8 {
        proxy_pass grp8;
        }
        http_chain chain1 {
        uri == "/static*" -> vh1;
        uri == "*.php" -> vh2;
        }
        http_chain chain2 {
        uri == "/foo/*" -> vh3;
        uri == "*.html" -> vh4;
        }
        http_chain chain3 {
        uri != "*hacked.com" -> chain1;
        -> block;
        }
        http_chain {
        hdr Host == "test.app.com" -> chain2;
        hdr User-Agent == "Mozilla*" -> chain2;
        hdr Referer == "*.com" -> chain1;
        hdr referer == "http://example.*" -> chain3;
        hdr host == "bad.host.com" -> block;
        hdr host == "bar*" -> vh5;
        cookie "tempesta" == "*" -> vh8;

        mark == 1 -> vh8;
        mark == 2 -> vh7;
        mark == 3 -> vh6;
        mark == 4 -> vh5;
        mark == 5 -> vh4;
        mark == 6 -> vh3;
        mark == 7 -> vh2;
        mark == 8 -> vh1;


        }
        """
    }

    clients = [
        {
            'id' : 0,
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        },
        {
            'id' : 1,
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        },
        {
            'id' : 2,
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        },
        {
            'id' : 3,
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        },
        {
            'id' : 4,
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        },
        {
            'id' : 5,
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        },
        {
            'id' : 6,
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        },
        {
            'id' : 7,
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        }
    ]

    requests_opt = [
        (
            ('/static/index.html'),
            ('referer'),
            ('example.com'),
            False
        ),
        (
            ('/script.php'),
            ('referer'),
            ('http://example.com/cgi-bin/show.pl'),
            False
        ),
        (
            ('/foo/example.com'),
            ('host'),
            ('test.app.com'),
            False
        ),
        (
            ('/bar/index.html'),
            ('user-agent'),
            ('Mozilla/60.0'),
            False
        ),
        (
            ('/static/foo/app/test.php'),
            ('host'),
            ('bar.example.com'),
            False
        ),
        (
            ('/app/hacked.com'),
            ('referer'),
            ('http://example.org'),
            True
        ),
        (
            ('/'),
            ('host'),
            ('bad.host.com'),
            True
        ),
                (
            ('/baz/index.html'),
            ('cookie'),
            ('tempesta=test'),
            False
        ),
    ]

    chains = []
    match_rules_test = True

    def init_chain(self, params):
        uri, header, value, block = params
        ch = chains.base(uri=uri)
        if block and self.match_rules_test:
            ch.request.headers.delete_all(header)
            ch.request.headers.add(header, value)
            ch.request.update()
            ch.fwd_request = None
        else:
            for request in [ch.request, ch.fwd_request]:
                request.headers.delete_all(header)
                request.headers.add(header, value)
                request.update()
        self.chains.append(ch)

    def setUp(self):
        del(self.chains[:])
        count = len(self.requests_opt)
        for i in range(count):
            self.init_chain(self.requests_opt[i])
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
        # Check if the connection alive (general case) or
        # not (case of 'block' rule matching) after the main
        # message processing. Response 404 is enough here.
        post_chain = chains.base()
        client.make_request(post_chain.request.msg)
        if chain.fwd_request:
            self.assertTrue(client.wait_for_response())
        else:
            self.assertFalse(client.wait_for_response())

    def test_chains(self):
        """Test for matching rules in HTTP chains: according to
        test configuration of HTTP tables, requests must be
        forwarded to the right vhosts according to it's
        headers content.
        """
        self.start_all()
        count = len(self.chains)
        for i in range(count):
            self.process(self.get_client(i),
                         self.get_server(i),
                         self.chains[i])

class HttpTablesTestMarkRules(HttpTablesTest):

    match_rules_test = False

    def set_nf_mark(self, mark):
        cmd = 'iptables -t mangle -A PREROUTING -p tcp -j MARK --set-mark %s' \
              % mark
        remote.tempesta.run_cmd(cmd, timeout=30)
        self.marked = mark

    def del_nf_mark(self, mark):
        cmd = 'iptables -t mangle -D PREROUTING -p tcp -j MARK --set-mark %s' \
              % mark
        remote.tempesta.run_cmd(cmd, timeout=30)
        self.marked = None

    def setUp(self):
        self.marked = None
        HttpTablesTest.setUp(self)

    def tearDown(self):
        if self.marked:
            self.del_nf_mark(self.marked)
        tester.TempestaTest.tearDown(self)

    def test_chains(self):
        """Test for mark rules in HTTP chains: requests must
        arrive to backends in reverse order, since mark rules are
        always processed before match rule (see HTTP tables
        configuration for current test - in @tempesta
        class variable).
        """
        self.start_all()
        count = len(self.chains)
        for i in range(count):
            mark = i + 1
            self.set_nf_mark(mark)
            self.process(self.get_client(i),
                         self.get_server(count - mark),
                         self.chains[i])
            self.del_nf_mark(mark)

TEMPESTA_CONFIG = """
    %s

    srv_group default {
            server ${server_ip}:8000;
    }

    vhost default {
            proxy_pass default;
    }

    %s
"""

class HttpTablesTestBase(tester.TempestaTest, base=True):

    clients = [
        {
            'id' : 'client',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80'
        }
    ]

    backends = [
        {
            'id' : '0',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' :
                'HTTP/1.1 200 OK\r\n'
                'Content-Length: 0\r\n\r\n'
        }
    ]

    tempesta = {
        'config' : TEMPESTA_CONFIG % ("", "")
    }

    resp_status = 200

    requests = "GET / HTTP/1.1\r\n" \
               "Host: tempesta-tech.com\r\n" \
               "\r\n"

    redirect_location = ""

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        srv = self.get_server('0')
        self.assertTrue(srv.wait_for_connections(timeout=1))

    def test(self):
        self.start_all()

        deproxy_cl = self.get_client('client')
        deproxy_cl.start()
        deproxy_cl.make_requests(self.requests)
        if (self.resp_status):
            self.assertTrue(deproxy_cl.wait_for_response())
            if self.redirect_location:
                self.assertEqual(deproxy_cl.last_response.headers['location'],
                                 self.redirect_location)
            self.assertEqual(int(deproxy_cl.last_response.status),
                             self.resp_status)
        else:
            self.assertFalse(deproxy_cl.wait_for_response())

class HttpTablesTestEmptyMainChainReply(HttpTablesTestBase):

    tempesta = {
        'config' : TEMPESTA_CONFIG % ("block_action attack reply;",
                                      "http_chain {}")
    }

    resp_status = 403

class HttpTablesTestEmptyMainChainDrop(HttpTablesTestBase):

    tempesta = {
        'config' : TEMPESTA_CONFIG % ("block_action attack drop;",
                                      "http_chain {}")
    }

    resp_status = 0

class HttpTablesTestEmptyMainChainDefault(HttpTablesTestBase):

    tempesta = {
        'config' : TEMPESTA_CONFIG % ("", "http_chain {}")
    }

    resp_status = 0

class HttpTablesTestEmptyChainReply(HttpTablesTestBase):

    tempesta = {
        'config' : TEMPESTA_CONFIG % ("block_action attack reply;", """
http_chain chain1 {}
http_chain {
    hdr Host == "tempesta-tech.com" -> chain1;
}""")
    }

    resp_status = 403

class HttpTablesTestEmptyChainDrop(HttpTablesTestBase):

    tempesta = {
        'config' : TEMPESTA_CONFIG % ("block_action attack drop;", """
http_chain chain1 {}
http_chain {
    hdr Host == "tempesta-tech.com" -> chain1;
}""")
    }

    resp_status = 0

class HttpTablesTestEmptyChainDefault(HttpTablesTestBase):

    tempesta = {
        'config' : TEMPESTA_CONFIG % ("", """
http_chain chain1 {}
http_chain {
    hdr Host == "tempesta-tech.com" -> chain1;
}""")
    }

    resp_status = 0

class HttpTablesTestMixedChainReply(HttpTablesTestBase):

    tempesta = {
        'config' : TEMPESTA_CONFIG % ("block_action attack reply;", """
http_chain chain1 {
    uri == "/static*" -> default;
}
http_chain {
    hdr Host == "tempesta-tech.com" -> chain1;
}""")
    }

    resp_status = 403

class HttpTablesTestMixedChainDrop(HttpTablesTestBase):

    tempesta = {
        'config' : TEMPESTA_CONFIG % ("block_action attack drop;", """
http_chain chain1 {
    uri == "/static*" -> default;
}
http_chain {
    hdr Host == "tempesta-tech.com" -> chain1;
}""")
    }

    resp_status = 0

class HttpTablesTestMixedChainDefault(HttpTablesTestBase):

    tempesta = {
        'config' : TEMPESTA_CONFIG % ("", """
http_chain chain1 {
    uri == "/static*" -> default;
}
http_chain {
    hdr Host == "tempesta-tech.com" -> chain1;
}""")
    }

    resp_status = 0

class HttpTablesTestMixedChainResp(HttpTablesTestBase):

    tempesta = {
        'config' : TEMPESTA_CONFIG % ("block_action attack reply;", """
http_chain chain1 {
    uri == "/static*" -> default;
}
http_chain {
    hdr Host == "tempesta-tech.com" -> chain1;
}""")
    }

    resp_status = 200

    requests = "GET /static HTTP/1.1\r\n" \
               "Host: tempesta-tech.com\r\n" \
               "\r\n"


# A block of tests to ensure that configuration variables $host and $request_uri work correctly.
class HttpTablesTestCustomRedirectCorrectVariables(HttpTablesTestBase):
    host = "tempesta-tech.com"
    request_uri = "/static"
    tempesta = {
        "config": TEMPESTA_CONFIG % ("", """
http_chain chain1 {
    uri == "%s*" -> 301 = https://static.$$host$$request_uri;

}
http_chain {
    hdr Host == "%s" -> chain1;
}""" % (request_uri, host))
    }

    resp_status = 301
    requests = f"GET {request_uri} HTTP/1.1\r\n" \
           f"Host: {host}\r\n" \
           "\r\n"
    redirect_location = f"https://static.{host}{request_uri}"


class HttpTablesTestCustomRedirectNonExistentVariables(HttpTablesTestBase):
    host = "tempesta-tech.com"
    request_uri = "/static"
    tempesta = {
        "config": TEMPESTA_CONFIG % ("", """
http_chain chain1 {
    uri == "%s*" -> 301 = https://$$urlfoo;
}
http_chain {
    hdr Host == "%s" -> chain1;

}""" % (request_uri, host))
    }
    resp_status = 301
    requests = f"GET {request_uri} HTTP/1.1\r\n" \
       f"Host: {host}\r\n" \
       "\r\n"
    redirect_location = "https://$urlfoo"


class HttpTablesTestCustomRedirectDifferentResponseStatus(HttpTablesTestBase):
    host = "tempesta-tech.com"
    request_uri = "/blog"
    tempesta = {
        "config": TEMPESTA_CONFIG % ("", """
http_chain chain1 {
    uri == "%s" -> 308 = https://$$host$$request_uri/new;

}
http_chain {
    hdr Host == "%s" -> chain1;
}""" % (request_uri, host))
    }

    resp_status = 308
    requests = f"GET {request_uri} HTTP/1.1\r\n" \
           f"Host: {host}\r\n" \
           "\r\n"
    redirect_location = f"https://{host}{request_uri}/new"


class HttpTablesTestCustomRedirectTooManyVariables(tester.TempestaTest):
    """
    More than 8 variables must be rejected on configuration process.
    """
    host = "tempesta-tech.com"
    request_uri = "/static"
    tempesta = {
        "config": TEMPESTA_CONFIG % ("", """
http_chain chain1 {
    uri == "%s*" -> 301 = https://$$host$$request_uri/$$host$$request_uri/$$host$$request_uri/$$host$$request_uri/$$host;

}
http_chain {
    hdr Host == "%s" -> chain1;
}""" % (request_uri, host))
    }
    def tearDown(self):
        pass

    def test(self):
        try:
            self.start_tempesta()
            started = True
        except Exception:
            started = False
        finally:
            self.assertFalse(started)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
