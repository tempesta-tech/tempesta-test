"""
Tests for JavaScript challenge.
"""

import abc
import re
import time

from framework import deproxy_client, tester
from framework.templates import fill_template, populate_properties
from helpers import remote, tempesta, tf_cfg
from helpers.deproxy import HttpMessage

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2020-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"


class BaseJSChallenge(tester.TempestaTest):
    def client_send_req(self, client, req):
        curr_responses = len(client.responses)
        client.make_request(req)
        client.wait_for_response(timeout=1)
        self.assertEqual(curr_responses + 1, len(client.responses))

        return client.responses[-1]

    def client_send_reqs(self, client, reqs):
        curr_responses = len(client.responses)
        client.make_requests(reqs, pipelined=True)
        client.wait_for_response()
        self.assertEqual(curr_responses + len(reqs), len(client.responses))

        return client.responses[-len(reqs) :]

    def client_expect_block(self, client, req, pipelined):
        curr_responses = len(client.responses)
        if pipelined:
            client.make_requests(req, pipelined=pipelined)
        else:
            client.make_request(req)
        client.wait_for_response(timeout=1)
        self.assertEqual(curr_responses, len(client.responses))
        self.assertTrue(client.wait_for_connection_close())

    @abc.abstractmethod
    def prepare_js_templates(self):
        pass

    def start_all(self):
        self.prepare_js_templates()
        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections(1))

    def prepare_first_req(self, client, host):
        if isinstance(client, deproxy_client.DeproxyClientH2):
            req = [
                (":authority", host),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
                ("accept", "text/html"),
            ]
        elif isinstance(client, deproxy_client.DeproxyClient):
            req = "GET / HTTP/1.1\r\nHost: %s\r\nAccept: text/html\r\n\r\n" % host

        return req

    def prepare_second_req(self, client, host, cookie):
        if isinstance(client, deproxy_client.DeproxyClientH2):
            req = [
                (":authority", host),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
                ("accept", "text/html"),
                ("cookie", f"{cookie[0]}={cookie[1]}"),
            ]
        elif isinstance(client, deproxy_client.DeproxyClient):
            req = (
                "GET / HTTP/1.1\r\n"
                "Host: %s\r\n"
                "Accept: text/html\r\n"
                "Cookie: %s=%s\r\n"
                "\r\n" % (host, cookie[0], cookie[1])
            )

        return req

    def check_resp_status_code_and_cookie(self, resp, delay_min, delay_range, status_code):
        self.assertEqual(resp.status, "%d" % status_code, "unexpected response status code")
        c_header = resp.headers.get("Set-Cookie", None)
        self.assertIsNotNone(c_header, "Set-Cookie header is missing in the response")
        match = re.search(r"([^;\s]+)=([^;\s]+)", c_header)
        self.assertIsNotNone(match, "Cant extract value from Set-Cookie header")
        cookie = (match.group(1), match.group(2))

        # Check that all the variables are passed correctly into JS challenge
        # code:
        js_vars = [
            'var c_name = "%s";' % cookie[0],
            "var delay_min = %d;" % delay_min,
            "var delay_range = %d;" % delay_range,
        ]
        for js_var in js_vars:
            self.assertIn(js_var, resp.body, "Can't find JS Challenge parameter in response body")
        return cookie

    def process_first_js_challenge_req(
        self,
        client,
        host,
        delay_min,
        delay_range,
        status_code,
    ):
        """Our tests can't pass the JS challenge with propper configuration,
        enlarge delay limit to not recommended values to make it possible to
        hardcode the JS challenge.
        """

        req = self.prepare_first_req(client, host)
        resp = self.client_send_req(client, req)
        cookie = self.check_resp_status_code_and_cookie(resp, delay_min, delay_range, status_code)
        req = self.prepare_second_req(client, host, cookie)

        return req, cookie

    def process_js_challenge(
        self,
        client,
        host,
        delay_min,
        delay_range,
        status_code,
        expect_pass,
        req_delay,
    ):
        req, cookie = self.process_first_js_challenge_req(
            client, host, delay_min, delay_range, status_code
        )

        # Pretend we can eval JS code and pass the challenge, but we can't set
        # reliable timeouts and pass the challenge on CI or in virtual
        # environments. Instead increase the JS parameters to make hardcoding
        # easy and reliable.
        if req_delay:
            time.sleep(req_delay)

        if not expect_pass:
            self.client_expect_block(client, req, False)
            return
        resp = self.client_send_req(client, req)
        self.assertEqual(resp.status, "200", "unexpected response status code")

    def process_js_challenge_pipelined(
        self,
        client,
        host,
        delay_min,
        delay_range,
        status_code,
        expect_pass,
        req_delay,
    ):
        req = self.prepare_first_req(client, host)
        resps = self.client_send_reqs(client, [req, req, req])

        reqs = []
        cookies = []
        for resp in resps:
            cookie = self.check_resp_status_code_and_cookie(
                resp, delay_min, delay_range, status_code
            )
            cookies.append(cookie)
            reqs.append(self.prepare_second_req(client, host, cookie))

        if req_delay:
            time.sleep(req_delay)

        if not expect_pass:
            self.client_expect_block(client, reqs, True)
            return
        resps = self.client_send_reqs(client, reqs)
        for resp in resps:
            self.assertEqual(resp.status, "200", "unexpected response status code")


class JSChallenge(BaseJSChallenge):
    """
    With sticky sessions enabled, client will be pinned to the same server,
    and only that server will respond to all its requests.

    There is no need to check different cookie names or per-vhost configuration,
    since basic cookie tests already prove that the cookie configuration is
    per-vhost.
    """

    backends = [
        {
            "id": "server-1",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + f"Date: {HttpMessage.date_time_string()}\r\n"
                + "Server: deproxy\r\n"
                + "Content-Length: 0\r\n\r\n"
            ),
        },
    ]

    tempesta = {
        "config": """
        server ${server_ip}:8000;

        vhost vh1 {
            proxy_pass default;
            sticky {
                cookie enforce name=cname;
                js_challenge resp_code=503 delay_min=1000 delay_range=1500
                            ${tempesta_workdir}/js1.html;
            }
        }

        vhost vh2 {
            proxy_pass default;
            sticky {
                cookie enforce;
                js_challenge resp_code=302 delay_min=2000 delay_range=1200
                            ${tempesta_workdir}/js2.html;
            }
        }

        vhost vh3 {
            proxy_pass default;
            sticky {
                cookie enforce;
                js_challenge delay_min=1000 delay_range=1000
                            ${tempesta_workdir}/js3.html;
            }
        }

        http_chain {
            host == "vh1.com" -> vh1;
            host == "vh2.com" -> vh2;
            host == "vh3.com" -> vh3;
            -> block;
        }
        """
    }

    clients = [
        {
            "id": "client-1",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
        {
            "id": "client-2",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
        {
            "id": "client-3",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    def prepare_js_templates(self):
        """
        Templates for JS challenge are modified by start script, create a copy
        of default template for each vhost.
        """
        srcdir = tf_cfg.cfg.get("Tempesta", "srcdir")
        workdir = tf_cfg.cfg.get("Tempesta", "workdir")
        template = "%s/etc/js_challenge.tpl" % srcdir
        js_code = "%s/etc/js_challenge.js.tpl" % srcdir
        remote.tempesta.run_cmd("cp %s %s" % (js_code, workdir))
        remote.tempesta.run_cmd("cp %s %s/js1.tpl" % (template, workdir))
        remote.tempesta.run_cmd("cp %s %s/js2.tpl" % (template, workdir))
        remote.tempesta.run_cmd("cp %s %s/js3.tpl" % (template, workdir))

    def test_get_challenge(self):
        """Not all requests are challengeable. Tempesta sends the challenge
        only if the client can accept it, i.e. request should has GET method and
        'Accept: text/html'. In other cases normal browsers don't eval
        JS code and TempestaFW is not trying to send the challenge to bots.
        """
        self.start_all()
        client = self.get_client("client-1")

        # Client can accept JS code in responses.
        if isinstance(client, deproxy_client.DeproxyClientH2):
            req = [
                (":authority", "vh1.com"),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
                ("accept", "text/html"),
            ]
        elif isinstance(client, deproxy_client.DeproxyClient):
            req = "GET / HTTP/1.1\r\nHost: vh1.com\r\nAccept: text/html\r\n\r\n"

        resp = self.client_send_req(client, req)
        self.assertEqual(resp.status, "503", "Unexpected response status code")
        self.assertIsNotNone(
            resp.headers.get("Set-Cookie", None), "Set-Cookie header is missing in the response"
        )
        match = re.search(r"(location\.replace)", resp.body)
        self.assertIsNotNone(match, "Can't extract redirect target from response body")

        if isinstance(client, deproxy_client.DeproxyClientH2):
            req = [
                (":authority", "vh1.com"),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
                ("accept", "*/*"),
            ]
        elif isinstance(client, deproxy_client.DeproxyClient):
            req = "GET / HTTP/1.1\r\nHost: vh1.com\r\nAccept: */*\r\n\r\n"

        client = self.get_client("client-2")
        self.client_expect_block(client, req, False)

        # Resource is not challengable, request will be blocked and the
        # connection will be reset.
        if isinstance(client, deproxy_client.DeproxyClientH2):
            req = [
                (":authority", "vh1.com"),
                (":path", "/"),
                (":scheme", "https"),
                (":method", "GET"),
                ("accept", "text/plain"),
            ]
        elif isinstance(client, deproxy_client.DeproxyClient):
            req = "GET / HTTP/1.1\r\nHost: vh1.com\r\nAccept: text/plain\r\n\r\n"

        client = self.get_client("client-3")
        self.client_expect_block(client, req, False)

    def test_pass_challenge(self):
        """Clients send the validating request just in time and pass the
        challenge.
        """
        self.start_all()

        client = self.get_client("client-1")
        self.process_js_challenge(
            client,
            "vh1.com",
            delay_min=1000,
            delay_range=1500,
            status_code=503,
            expect_pass=True,
            req_delay=2.5,
        )

        client = self.get_client("client-2")
        self.process_js_challenge(
            client,
            "vh2.com",
            delay_min=2000,
            delay_range=1200,
            status_code=302,
            expect_pass=True,
            req_delay=3.5,
        )
        # Vhost 3 has very strict window to receive the request, skip it in
        # this test.

    def test_pass_challenge_pipelined(self):
        self.start_all()

        client = self.get_client("client-1")
        self.process_js_challenge_pipelined(
            client,
            "vh1.com",
            delay_min=1000,
            delay_range=1500,
            status_code=503,
            expect_pass=True,
            req_delay=2.5,
        )

        client = self.get_client("client-2")
        self.process_js_challenge_pipelined(
            client,
            "vh2.com",
            delay_min=2000,
            delay_range=1200,
            status_code=302,
            expect_pass=True,
            req_delay=3.5,
        )
        # Vhost 3 has very strict window to receive the request, skip it in
        # this test.

    def test_fail_challenge_too_early(self):
        """Clients send the validating request too early, Tempesta closes the
        connection.
        """
        self.start_all()

        client = self.get_client("client-1")
        self.process_js_challenge(
            client,
            "vh1.com",
            delay_min=1000,
            delay_range=1500,
            status_code=503,
            expect_pass=False,
            req_delay=0,
        )

        client = self.get_client("client-2")
        self.process_js_challenge(
            client,
            "vh2.com",
            delay_min=2000,
            delay_range=1200,
            status_code=302,
            expect_pass=False,
            req_delay=1,
        )

        client = self.get_client("client-3")
        self.process_js_challenge(
            client,
            "vh3.com",
            delay_min=1000,
            delay_range=1000,
            status_code=503,
            expect_pass=False,
            req_delay=0,
        )

    def test_fail_challenge_too_early_pipelined(self):
        """Clients send the validating request too early, Tempesta closes the
        connection.
        """
        self.start_all()

        client = self.get_client("client-1")
        self.process_js_challenge_pipelined(
            client,
            "vh1.com",
            delay_min=1000,
            delay_range=1500,
            status_code=503,
            expect_pass=False,
            req_delay=0,
        )

        client = self.get_client("client-2")
        self.process_js_challenge_pipelined(
            client,
            "vh2.com",
            delay_min=2000,
            delay_range=1200,
            status_code=302,
            expect_pass=False,
            req_delay=1,
        )

        client = self.get_client("client-3")
        self.process_js_challenge_pipelined(
            client,
            "vh3.com",
            delay_min=1000,
            delay_range=1000,
            status_code=503,
            expect_pass=False,
            req_delay=0,
        )

    def client_send_custom_req(self, client, uri, cookie, host=None):
        if not host:
            host = "localhost"

        if isinstance(client, deproxy_client.DeproxyClientH2):
            req = [
                (":authority", host),
                (":path", uri),
                (":scheme", "https"),
                (":method", "GET"),
            ]
        elif isinstance(client, deproxy_client.DeproxyClient):
            req = (
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "%s"
                "\r\n" % (uri, host, ("Cookie: %s=%s\r\n" % cookie) if cookie else "")
            )
        response = self.client_send_req(client, req)

        self.assertEqual(response.status, "302", "unexpected response status code")
        c_header = response.headers.get("Set-Cookie", None)
        self.assertIsNotNone(c_header, "Set-Cookie header is missing in the response")
        match = re.search(r"([^;\s]+)=([^;\s]+)", c_header)
        self.assertIsNotNone(match, "Cant extract value from Set-Cookie header")
        cookie = (match.group(1), match.group(2))

        uri = response.headers.get("Location", None)
        self.assertIsNotNone(uri, "Location header is missing in the response")
        return (uri, cookie)

    def client_send_first_req(self, client, uri, host=None):
        return self.client_send_custom_req(client, uri, None, host=host)

    def get_config_without_js(self):
        """Recreate config without js_challenge directive."""
        desc = self.tempesta.copy()
        populate_properties(desc)
        new_cfg = fill_template(desc["config"], desc)
        new_cfg = re.sub(r"js_challenge[\s\w\d_/=\.\n]+;", "", new_cfg, re.M)
        return new_cfg

    def test_disable_challenge_on_reload(self):
        """Test on disable JS Challenge after reload"""
        self.start_all()

        # Reloading Tempesta config with JS challenge disabled.
        config = tempesta.Config()
        config.set_defconfig(self.get_config_without_js())

        self.get_tempesta().config = config
        self.get_tempesta().reload()

        client = self.get_client("client-1")
        uri = "/"
        vhost = "vh1.com"
        uri, cookie = self.client_send_first_req(client, uri, host=vhost)

        if isinstance(client, deproxy_client.DeproxyClientH2):
            req = [
                (":authority", vhost),
                (":path", uri.split("https:/")[1]),
                (":scheme", "https"),
                (":method", "GET"),
                ("cookie", f"{cookie[0]}={cookie[1]}"),
            ]
        elif isinstance(client, deproxy_client.DeproxyClient):
            req = (
                "GET %s HTTP/1.1\r\n"
                "Host: %s\r\n"
                "Cookie: %s=%s\r\n"
                "\r\n" % (uri, vhost, cookie[0], cookie[1])
            )

        response = self.client_send_req(client, req)
        self.assertEqual(response.status, "200", "unexpected response status code")


class JSChallengeH2(JSChallenge):
    tempesta = {
        "config": (
            "listen 443 proto=h2;\n"
            + JSChallenge.tempesta["config"]
            + """
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;
            """
        )
    }

    clients = [
        {
            "id": "client-1",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "client-2",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
        {
            "id": "client-3",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "port": "443",
            "ssl": True,
        },
    ]


class JSChallengeVhost(JSChallenge):
    """Same as JSChallenge, but 'sticky' configuration is inherited from
    updated defaults for the named vhosts.
    """

    tempesta = {
        "config": """
        server ${server_ip}:8000;

        sticky {
            cookie enforce name=cname;
            js_challenge resp_code=503 delay_min=1000 delay_range=1500
                         ${tempesta_workdir}/js1.html;
        }
        vhost vh1 {
            proxy_pass default;
        }

        sticky {
            cookie enforce;
            js_challenge resp_code=302 delay_min=2000 delay_range=1200
                         ${tempesta_workdir}/js2.html;
        }
        vhost vh2 {
            proxy_pass default;
        }


        sticky {
            cookie enforce;
            js_challenge delay_min=1000 delay_range=1000
                           ${tempesta_workdir}/js3.html;
        }
        vhost vh3 {
            proxy_pass default;
        }

        vhost vh4 {
            proxy_pass default;

            sticky {
                cookie enforce;
            }
        }

        http_chain {
            host == "vh1.com" -> vh1;
            host == "vh2.com" -> vh2;
            host == "vh3.com" -> vh3;
            host == "vh4.com" -> vh4;
            -> block;
        }
        """
    }

    def test_js_overriden_together_with_cookie(self):
        """Vhost `vh4` overrides `sticky` directive using only `cookie`
        directive. JS challenge is always derived with `cookie` directive, so
        JS challenge will be disabled for this vhost.
        """
        self.start_all()

        client = self.get_client("client-1")
        uri = "/"
        vhost = "vh4.com"
        uri, cookie = self.client_send_first_req(client, uri, host=vhost)

        req = (
            "GET %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Cookie: %s=%s\r\n"
            "\r\n" % (uri, vhost, cookie[0], cookie[1])
        )
        response = self.client_send_req(client, req)
        self.assertEqual(response.status, "200", "unexpected response status code")


class JSChallengeDefVhostInherit(BaseJSChallenge):
    """
    Implicit default vhost use other implementation of `sticky` inheritance.
    Check that correct configuration is derived.
    """

    backends = [
        {
            "id": "server-1",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        },
    ]

    tempesta = {
        "config": """
        server ${server_ip}:8000;

        sticky {
            cookie enforce name=cname;
            js_challenge resp_code=503 delay_min=1000 delay_range=1500
                         ${tempesta_workdir}/js1.html;
        }
        """
    }

    clients = [
        {
            "id": "client-1",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
        {
            "id": "client-2",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
        {
            "id": "client-3",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    def prepare_js_templates(self):
        """
        Templates for JS challenge are modified by start script, create a copy
        of default template for each vhost.
        """
        srcdir = tf_cfg.cfg.get("Tempesta", "srcdir")
        workdir = tf_cfg.cfg.get("Tempesta", "workdir")
        template = "%s/etc/js_challenge.tpl" % srcdir
        js_code = "%s/etc/js_challenge.js.tpl" % srcdir
        remote.tempesta.run_cmd("cp %s %s" % (js_code, workdir))
        remote.tempesta.run_cmd("cp %s %s/js1.tpl" % (template, workdir))

    def test_pass_challenge(self):
        """Clients send the validating request just in time and pass the
        challenge.
        """
        self.start_all()

        client = self.get_client("client-1")
        self.process_js_challenge(
            client,
            "vh1.com",
            delay_min=1000,
            delay_range=1500,
            status_code=503,
            expect_pass=True,
            req_delay=2.5,
        )


class JSChallengeAfterReload(BaseJSChallenge):
    # Test on enable JS Challenge after reload

    backends = [
        {
            "id": "server-1",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        },
    ]

    tempesta = {
        "config": """
        server ${server_ip}:8000;

        sticky {
            cookie enforce name=cname;
        }
        """
    }

    clients = [
        {
            "id": "client-1",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        },
    ]

    def prepare_js_templates(self):
        """
        Templates for JS challenge are modified by start script, create a copy
        of default template for each vhost.
        """
        srcdir = tf_cfg.cfg.get("Tempesta", "srcdir")
        workdir = tf_cfg.cfg.get("Tempesta", "workdir")
        template = "%s/etc/js_challenge.tpl" % srcdir
        js_code = "%s/etc/js_challenge.js.tpl" % srcdir
        remote.tempesta.run_cmd("cp %s %s" % (js_code, workdir))
        remote.tempesta.run_cmd("cp %s %s/js1.tpl" % (template, workdir))

    def test(self):
        """Clients sends the validating request after reload just in time and
        passes the challenge.
        """
        self.start_all()

        # Reloading Tempesta config with JS challenge enabled
        config = tempesta.Config()
        config.set_defconfig(
            """
        server %s:8000;

        sticky {
            cookie enforce name=cname;
            js_challenge resp_code=503 delay_min=1000 delay_range=1500
                         %s/js1.html;
        }
        """
            % (tf_cfg.cfg.get("Server", "ip"), tf_cfg.cfg.get("Tempesta", "workdir"))
        )
        self.get_tempesta().config = config
        self.get_tempesta().reload()

        client = self.get_client("client-1")
        self.process_js_challenge(
            client,
            "vh1.com",
            delay_min=1000,
            delay_range=1500,
            status_code=503,
            expect_pass=True,
            req_delay=2.5,
        )
