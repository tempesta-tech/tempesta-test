"""
Tests for JavaScript challenge.
"""

import abc
import re
import time

from framework import deproxy_client, tester
from framework.parameterize import param, parameterize, parameterize_class
from framework.templates import fill_template, populate_properties
from helpers import remote, tempesta, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2020-2023 Tempesta Technologies, Inc."
__license__ = "GPL2"


class BaseJSChallenge(tester.TempestaTest):
    def client_send_reqs(self, client, reqs):
        curr_responses = len(client.responses)
        client.make_requests(reqs, pipelined=True)
        client.wait_for_response()
        self.assertEqual(curr_responses + len(reqs), len(client.responses))

        return client.responses[-len(reqs) :]

    def client_expect_block(self, client, req, is_single=True):
        if is_single:
            client.make_request(req)
        else:
            client.make_requests(req, pipelined=True)

        self.assertFalse(client.wait_for_response())
        self.assertTrue(client.conn_is_closed)

    def start_all(self):
        self.prepare_js_templates()
        self.start_all_services()

    def check_resp_on_restart(self, resp, status_code, last_cookie):
        self.assertEqual(resp.status, "%d" % status_code, "unexpected response status code")
        c_header = resp.headers.get("Set-Cookie", None)
        self.assertIsNotNone(c_header, "Set-Cookie header is missing in the response")
        match = re.search(r"([^;\s]+)=([^;\s]+)", c_header)
        self.assertIsNotNone(match, "Can't extract value from Set-Cookie header")
        new_cookie = (match.group(1), match.group(2))
        self.assertNotEqual(last_cookie, new_cookie, "Challenge is not restarted")

    def expect_restart(self, client, req, status_code, last_cookie):
        """
        We tried to pass JS challenge, but the cookie we have was generated
        too long time ago. We can't pass JS challenge now, but Tempesta
        doesn't block us, but gives second chance to pass the challenge.

        Expect a new redirect response with new sticky cookie value.
        """
        client.send_request(req, status_code)
        self.check_resp_on_restart(client.last_response, status_code, last_cookie)

    def expect_restart_pipelined(self, client, reqs, status_code, last_cookies):
        resps = self.client_send_reqs(client, reqs)
        self.assertEqual(len(resps), len(last_cookies))
        cookie_num = 0
        for resp in resps:
            self.check_resp_on_restart(resp, status_code, last_cookies[cookie_num])
            cookie_num += 1

    @staticmethod
    def prepare_first_req(client):
        return client.create_request(method="GET", headers=[("accept", "text/html")])

    @staticmethod
    def prepare_second_req(client, cookie: tuple):
        return client.create_request(
            method="GET",
            headers=[("accept", "text/html"), ("cookie", f"{cookie[0]}={cookie[1]}")],
        )

    def _check_and_get_cookie(self, resp) -> tuple:
        c_header = resp.headers.get("Set-Cookie", None)
        self.assertIsNotNone(c_header, "Set-Cookie header is missing in the response")
        match = re.search(r"([^;\s]+)=([^;\s]+)", c_header)
        self.assertIsNotNone(match, "Cant extract value from Set-Cookie header")
        return match.group(1), match.group(2)

    def check_resp_body_and_cookie(self, resp):
        cookie = self._check_and_get_cookie(resp)
        # Check that all the variables are passed correctly into JS challenge
        # code:
        js_vars = [
            'var c_name = "%s";' % cookie[0],
            "var delay_min = %d;" % self.delay_min,
            "var delay_range = %d;" % self.delay_range,
        ]
        for js_var in js_vars:
            self.assertIn(js_var, resp.body, "Can't find JS Challenge parameter in response body")
        return cookie

    def process_first_js_challenge_req(self, client):
        """
        Our tests can't pass the JS challenge with propper configuration,
        enlarge delay limit to not recommended values to make it possible to
        hardcode the JS challenge.
        """
        client.send_request(self.prepare_first_req(client), "503")
        return self.check_resp_body_and_cookie(client.last_response)

    def process_js_challenge(
        self,
        client,
        host,
        delay_min,
        delay_range,
        status_code,
        expect_pass,
        req_delay: bool,
        restart_on_fail=False,
    ):
        req, cookie = self.process_first_js_challenge_req(
            client, host, delay_min, delay_range, status_code
        )

        # Pretend we can eval JS code and pass the challenge, but we can't set
        # reliable timeouts and pass the challenge on CI or in virtual
        # environments. Instead increase the JS parameters to make hardcoding
        # easy and reliable.
        if req_delay:
            # this repeats sleep from JavaScript in response body
            time.sleep(req_delay)

        if not expect_pass:
            if restart_on_fail:
                self.expect_restart(client, req, status_code, cookie)
            else:
                self.client_expect_block(client, req)
            return
        client.send_request(req, "200")

    def process_js_challenge_pipelined(
        self,
        client,
        host,
        delay_min,
        delay_range,
        status_code,
        expect_pass,
        req_delay,
        restart_on_fail=False,
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
            if restart_on_fail:
                self.expect_restart_pipelined(client, reqs, status_code, cookies)
            else:
                self.client_expect_block(client, reqs, False)
            return
        resps = self.client_send_reqs(client, reqs)
        for resp in resps:
            self.assertEqual(resp.status, "200", "unexpected response status code")


class JSChallenge(BaseJSChallenge):
    max_misses = 2
    delay_min = 1000
    delay_range = 1500

    backends = [
        {
            "id": "server-1",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + "Date: test\r\n"
                + "Server: deproxy\r\n"
                + "Content-Length: 0\r\n\r\n"
            ),
        },
    ]

    tempesta = {
        "config": f"""
        server ${{server_ip}}:8000;
        
        block_action attack reply;
        block_action error reply;
        
        sticky {{
            cookie enforce name=cname max_misses={max_misses};
            js_challenge resp_code=503 delay_min={delay_min} delay_range={delay_range} 
                        ${{tempesta_workdir}}/js1.html;
        }}
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

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        srcdir = tf_cfg.cfg.get("Tempesta", "srcdir")
        workdir = tf_cfg.cfg.get("Tempesta", "workdir")
        remote.tempesta.run_cmd(f"cp {srcdir}/etc/js_challenge.js.tpl {workdir}")
        remote.tempesta.run_cmd(f"cp {srcdir}/etc/js_challenge.tpl {workdir}/js1.tpl")

    def _java_script_sleep(self, cookie: str) -> None:
        """This repeats sleep from JavaScript in response body"""
        time.sleep((self.delay_min + int(cookie[:16], 16) % self.delay_range) / 1000)

    def _reload_tempesta_without_js_config(self):
        """Recreate config without js_challenge directive."""
        desc = self.tempesta.copy()
        populate_properties(desc)
        new_cfg = fill_template(desc["config"], desc)
        new_cfg = re.sub(r"js_challenge[\s\w\d_/=\.\n]+;", "", new_cfg, re.M)

        self.get_tempesta().config.set_defconfig(new_cfg)
        self.get_tempesta().reload()

    @parameterize.expand(
        [
            param(name="GET_and_accept_html", method="GET", accept="text/html", status="503"),
            param(name="GET_and_accept_all", method="GET", accept="*/*", status="400"),
            param(name="GET_and_accept_image", method="GET", accept="image/*", status="400"),
            param(name="GET_and_accept_plain", method="GET", accept="text/plain", status="400"),
            param(name="POST", accept="text/html", method="POST", hstatus="400"),
        ]
    )
    def test_first_request(self, name, method, accept, status):
        """
        Not all requests are challengeable. Tempesta sends the challenge
        only if the client can accept it, i.e. request should has GET method and
        'Accept: text/html'. In other cases normal browsers don't eval
        JS code and TempestaFW is not trying to send the challenge to bots.
        """
        self.start_all_services()

        client = self.get_client("client-1")
        client.send_request(
            client.create_request(method=method, headers=[("accept", accept)]),
            status,
        )
        resp = client.last_response

        self.assertIsNotNone(
            resp.headers.get("Set-Cookie", None), "Set-Cookie header is missing in the response"
        )
        if status == "503":
            self.check_resp_body_and_cookie(resp)
        else:
            self.assertEqual(
                resp.body,
                "",
                f"Tempesta send a response body for a reqeust with {method} method and "
                f"accept header - {accept}",
            )

    def test_second_request(self):
        self.start_all_services()

        client = self.get_client("client-1")
        self.process_first_js_challenge_req(client)

    @parameterize.expand(
        [
            param(name="pass", sleep=True, second_status="200", conn_is_closed=False),
            param(name="too_small", sleep=False, second_status="400", conn_is_closed=True),
        ]
    )
    def test_delay(self, name, sleep, second_status, conn_is_closed):
        """
        The client MUST repeat a request between min_time and max_time when:
            - min_time = delay_min + (value between 0 and delay_range);
        """
        self.start_all_services()

        client = self.get_client("client-1")
        cookie = self.process_first_js_challenge_req(client)

        if sleep:
            self._java_script_sleep(cookie[1])

        client.send_request(
            request=self.prepare_second_req(client, cookie),
            expected_status_code=second_status,
        )
        self.assertEqual(client.conn_is_closed, conn_is_closed)

    def test_restart_js_challenge(self):
        """
        Tempesta MUST restart JS challenge when client make request with invalid cookie
        and the number of requests is less than `max_misses`.
        """
        self.start_all_services()
        invalid_cookie = ("cname", "0000000100116a72fd67776d455aacf0dda1b56e570a109c89cd5582")
        client = self.get_client("client-1")

        # make first request without cookie, request misses = 1
        client.send_request(
            request=self.prepare_second_req(client, invalid_cookie),
            expected_status_code="503",
        )
        cookie_1 = self.check_resp_body_and_cookie(client.last_response)

        self._java_script_sleep(cookie_1[1])

        client.send_request(self.prepare_second_req(client, cookie_1), expected_status_code="200")
        self.assertNotEqual(invalid_cookie[1], cookie_1[1], "Tempesta did not restart JS challenge")

    def test_number_of_requests_is_greater_than_max_misses(self):
        """
        The client make several tries to bypass JS challenge.
        Tempesta MUST block client when the number of requests is greater than `max_misses'.
        """
        client = self.get_client("client-1")
        self.start_all_services()

        # make first request without cookie, request misses = 1
        cookie = self.process_first_js_challenge_req(client)

        # make second request without cookie, request misses = 2
        self._java_script_sleep(cookie[1])
        cookie = self.process_first_js_challenge_req(client)

        # make third request without cookie, request misses = 3
        self._java_script_sleep(cookie[1])
        client.send_request(self.prepare_first_req(client), expected_status_code="400")
        client.wait_for_connection_close(strict=True)

    def test_disable_challenge_on_reload(self):
        """
        Test on disable JS Challenge after reload.
        The second request without sleep from JS challenge must be successful.
        """
        self.start_all_services()

        # Reloading Tempesta config with JS challenge disabled.
        self._reload_tempesta_without_js_config()

        client = self.get_client("client-1")
        client.send_request(
            request=client.create_request(method="GET", headers=[]),
            expected_status_code="302",
        )
        cookie = self._check_and_get_cookie(client.last_response)

        client.send_request(
            request=client.create_request(
                method="GET",
                headers=[("cookie", f"{cookie[0]}={cookie[1]}")],
            ),
            expected_status_code="200",
        )

    def test_not_block_after_tempesta_restart(self):
        self.start_all_services()
        client = self.get_client("client-1")

        # browser make request and wait for time from JS challenge
        cookie_1 = self.process_first_js_challenge_req(client)
        self._java_script_sleep(cookie_1[1])

        # browser make valid request and close session
        client.send_request(self.prepare_second_req(client, cookie_1), expected_status_code="200")
        client.stop()

        # Tempesta reboots
        self.get_tempesta().restart()

        # browser create a new session with an existing cookie.
        # This cookie valid for browser, but invalid for Tempesta
        # because it has other timestamp after reboot
        client.start()
        client.send_request(self.prepare_second_req(client, cookie_1), expected_status_code="503")
        cookie_2 = self._check_and_get_cookie(client.last_response)

        #
        self._java_script_sleep(cookie_2[1])
        client.send_request(self.prepare_second_req(client, cookie_2), expected_status_code="200")


class JSChallenge2(BaseJSChallenge):
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
                + "Date: test\r\n"
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
                            delay_limit=5000 ${tempesta_workdir}/js1.html;
            }
        }

        vhost vh2 {
            proxy_pass default;
            sticky {
                cookie enforce;
                js_challenge resp_code=302 delay_min=2000 delay_range=1200
                            delay_limit=5000 ${tempesta_workdir}/js2.html;
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

    def test_pass_challenge_pipelined(self):
        self.start_all_services()

        client = self.get_client("client-1")
        self.process_js_challenge_pipelined(
            client,
            "vh1.com",
            delay_min=1000,
            delay_range=1500,
            status_code=503,
            expect_pass=True,
            req_delay=2,
        )

        client = self.get_client("client-2")
        self.process_js_challenge_pipelined(
            client,
            "vh2.com",
            delay_min=2000,
            delay_range=1200,
            status_code=302,
            expect_pass=True,
            req_delay=2.5,
        )

    def test_fail_challenge_too_early_pipelined(self):
        """
        Clients send the validating request too early, Tempesta closes the
        connection.
        """
        self.start_all_services()

        tf_cfg.dbg(3, "Send requests to vhost 1 with timeout 0s...")
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

        tf_cfg.dbg(3, "Send requests to vhost 2 with timeout 1s...")
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

        tf_cfg.dbg(3, "Send requests to vhost 3 with timeout 0s...")
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

    def test_fail_challenge_too_late_restart_success_pipelined(self):
        """
        Clients send the validating request too late, Tempesta restarts
        cookie challenge.
        """
        self.start_all_services()

        tf_cfg.dbg(3, "Send requests to vhost 1 with timeout 4s...")
        client = self.get_client("client-1")
        self.process_js_challenge_pipelined(
            client,
            "vh1.com",
            delay_min=1000,
            delay_range=1500,
            status_code=503,
            expect_pass=False,
            req_delay=4,
            restart_on_fail=True,
        )

        tf_cfg.dbg(3, "Send requests to vhost 2 with timeout 4s...")
        client = self.get_client("client-2")
        self.process_js_challenge_pipelined(
            client,
            "vh2.com",
            delay_min=2000,
            delay_range=1200,
            status_code=302,
            expect_pass=False,
            req_delay=4,
            restart_on_fail=True,
        )

        tf_cfg.dbg(3, "Send requests to vhost 3 with timeout 8s...")
        client = self.get_client("client-3")
        # if delay_limit is not set it is set to delay_range * 10
        self.process_js_challenge_pipelined(
            client,
            "vh3.com",
            delay_min=1000,
            delay_range=1000,
            status_code=503,
            expect_pass=False,
            req_delay=8,
            restart_on_fail=True,
        )

    def test_fail_challenge_too_late_restart_fail_pipelined(self):
        """
        Clients send the validating request too late (after
        delay_limit), Tempesta block request.
        """
        self.start_all_services()

        tf_cfg.dbg(3, "Send requests to vhost 1 with timeout 7s...")
        client = self.get_client("client-1")
        self.process_js_challenge_pipelined(
            client,
            "vh1.com",
            delay_min=1000,
            delay_range=1500,
            status_code=503,
            expect_pass=False,
            req_delay=7,
        )

        tf_cfg.dbg(3, "Send requests to vhost 2 with timeout 8s...")
        client = self.get_client("client-2")
        self.process_js_challenge_pipelined(
            client,
            "vh2.com",
            delay_min=2000,
            delay_range=1200,
            status_code=302,
            expect_pass=False,
            req_delay=8,
        )

        tf_cfg.dbg(3, "Send requests to vhost 3 with timeout 12s...")
        client = self.get_client("client-3")
        # if delay_limit is not set it is set to delay_range * 10
        self.process_js_challenge_pipelined(
            client,
            "vh3.com",
            delay_min=1000,
            delay_range=1000,
            status_code=503,
            expect_pass=False,
            req_delay=12,
        )


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
    """
    Same as JSChallenge, but 'sticky' configuration is inherited from
    updated defaults for the named vhosts.
    """

    tempesta = {
        "config": """
        server ${server_ip}:8000;

        sticky {
            cookie enforce name=cname;
            js_challenge resp_code=503 delay_min=1000 delay_range=1500
                         delay_limit=5000 ${tempesta_workdir}/js1.html;
        }
        vhost vh1 {
            proxy_pass default;
        }

        sticky {
            cookie enforce;
            js_challenge resp_code=302 delay_min=2000 delay_range=1200
                         delay_limit=5000 ${tempesta_workdir}/js2.html;
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
        """
        Vhost `vh4` overrides `sticky` directive using only `cookie`
        directive. JS challenge is always derived with `cookie` directive, so
        JS challenge will be disabled for this vhost.
        """
        self.start_all_services()

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
                         delay_limit=3000 ${tempesta_workdir}/js1.html;
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
        """
        Clients send the validating request just in time and pass the
        challenge.
        """
        self.start_all_services()

        tf_cfg.dbg(3, "Send request to default vhost with timeout 2s...")
        client = self.get_client("client-1")
        self.process_js_challenge(
            client,
            "vh1.com",
            delay_min=1000,
            delay_range=1500,
            status_code=503,
            expect_pass=True,
            req_delay=2,
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
        """
        Clients sends the validating request after reload just in time and
        passes the challenge.
        """
        self.start_all_services()

        # Reloading Tempesta config with JS challenge enabled
        config = tempesta.Config()
        config.set_defconfig(
            """
        server %s:8000;

        sticky {
            cookie enforce name=cname;
            js_challenge resp_code=503 delay_min=1000 delay_range=1500
                         delay_limit=3000 %s/js1.html;
        }
        """
            % (tf_cfg.cfg.get("Server", "ip"), tf_cfg.cfg.get("Tempesta", "workdir"))
        )
        self.get_tempesta().config = config
        self.get_tempesta().reload()

        tf_cfg.dbg(3, "Send request to vhost 1 with timeout 2s...")
        client = self.get_client("client-1")
        self.process_js_challenge(
            client,
            "vh1.com",
            delay_min=1000,
            delay_range=1500,
            status_code=503,
            expect_pass=True,
            req_delay=2,
        )


class JSChallengeMaxAge(BaseJSChallenge):
    # Test Max Age cookie option.
    backends = [
        {
            "id": "server-1",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                + "Date: test\r\n"
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
                cookie enforce;
                js_challenge resp_code=503 delay_min=1000 delay_range=1500
                            delay_limit=3000 ${tempesta_workdir}/js1.html;
            }
        }

        vhost vh2 {
            proxy_pass default;
            sticky {
                cookie enforce;
                sess_lifetime 5;
                js_challenge resp_code=503 delay_min=1000 delay_range=4000
                            ${tempesta_workdir}/js2.html;
            }
        }

        http_chain {
            host == "vh1.com" -> vh1;
            host == "vh2.com" -> vh2;
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

    def send_req_and_check_cookie_max_age(self, client, host, status_code, max_age):
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

        resp = self.client_send_req(client, req)
        self.assertEqual(resp.status, "%d" % status_code, "unexpected response status code")
        c_header = resp.headers.get("Set-Cookie", None)
        self.assertIsNotNone(c_header, "Set-Cookie header is missing in the response")
        match = re.search(r"(Max-Age)=([^;\s]+)", c_header)
        self.assertIsNotNone(match, "Can't extract max-age value from Set-Cookie header")
        self.assertEqual(match[2], max_age)

    def test_max_age_no_session_lifetime(self):
        self.start_all_services()
        client = self.get_client("client-1")
        self.send_req_and_check_cookie_max_age(client, "vh1.com", 503, "4294967295")

    def test_max_age_with_session_lifetime(self):
        self.start_all_services()
        client = self.get_client("client-2")
        self.send_req_and_check_cookie_max_age(client, "vh2.com", 503, "5")

    def test_sticky_cookie_expired(self):
        self.start_all_services()
        client = self.get_client("client-2")
        req1, cookie1 = self.process_first_js_challenge_req(
            client,
            "vh2.com",
            delay_min=1000,
            delay_range=4000,
            status_code=503,
        )

        time.sleep(2.5)

        resp = self.client_send_req(client, req1)
        self.assertEqual(resp.status, "200", "unexpected response status code")

        time.sleep(4)

        # Sticky cookie expired, restart JS challenge
        req2, cookie2 = self.process_first_js_challenge_req(
            client,
            "vh2.com",
            delay_min=1000,
            delay_range=4000,
            status_code=503,
        )

        time.sleep(2.5)

        resp = self.client_send_req(client, req2)
        self.assertEqual(resp.status, "200", "unexpected response status code")

        self.assertNotEqual(cookie1[1], cookie2[1])


class JSChallengeMaxAgeH2(JSChallengeMaxAge):
    tempesta = {
        "config": (
            "listen 443 proto=h2;\n"
            + JSChallengeMaxAge.tempesta["config"]
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
    ]


class JSChallengeDisallowedOptions(tester.TempestaTest):
    tempesta_path_in_options_lc = {
        "config": """
        sticky {
            cookie enforce options=\"HttpOnly; path=/\";
        }
        """
    }

    tempesta_path_in_options_uc = {
        "config": """
        sticky {
            cookie enforce options=\"HttpOnly; Path=/\";
        }
        """
    }

    tempesta_max_age_in_options_lc = {
        "config": """
        sticky {
            cookie enforce options=\"HttpOnly; max-age=1\";
        }
        """
    }

    tempesta_max_age_in_options_uc = {
        "config": """
        sticky {
            cookie enforce options=\"HttpOnly; Max-Age=1\";
        }
        """
    }

    def start_fail(self, config):
        started = None
        self.oops_ignore = ["WARNING", "ERROR"]
        tempesta = self.get_tempesta()
        tempesta.config.set_defconfig(config["config"])
        try:
            self.start_tempesta()
            started = True
        except Exception:
            started = False
        finally:
            self.assertFalse(started)

    def test_tempesta_path_in_options_lc(self):
        self.start_fail(self.tempesta_path_in_options_lc)

    def test_tempesta_path_in_options_uc(self):
        self.start_fail(self.tempesta_path_in_options_uc)

    def test_tempesta_max_age_in_options_lc(self):
        self.start_fail(self.tempesta_max_age_in_options_lc)

    def test_tempesta_max_age_in_options_uc(self):
        self.start_fail(self.tempesta_max_age_in_options_uc)
