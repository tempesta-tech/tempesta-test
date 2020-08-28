"""
Tests for JavaScript challenge.
"""

import abc
import re
import time
from helpers import tempesta, tf_cfg, remote
from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2020 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class BaseJSChallenge(tester.TempestaTest):
    def wait_all_connections(self, tmt=1):
        sids = self.get_servers_id()
        for sid in sids:
            srv = self.get_server(sid)
            if not srv.wait_for_connections(timeout=tmt):
                return False
        return True

    def client_send_req(self, client, req):
        curr_responses = len(client.responses)
        client.make_requests(req)
        client.wait_for_response(timeout=1)
        self.assertEqual(curr_responses + 1, len(client.responses))

        return client.responses[-1]

    def client_expect_block(self, client, req):
        curr_responses = len(client.responses)
        client.make_requests(req)
        client.wait_for_response(timeout=1)
        self.assertEqual(curr_responses, len(client.responses))
        self.assertTrue(client.connection_is_closed())

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

    def expect_restart(self, client, req, status_code, last_cookie):
        """We tried to pass JS challenge, but the cookie we have was generated
        too long time ago. We can't pass JS challenge now, but Tempesta
        doesn't block us, but gives second chance to pass the challenge.

        Expect a new redirect response with new sticky cookie value.
        """
        resp = self.client_send_req(client, req)
        self.assertEqual(resp.status, '%d' % status_code,
                         "unexpected response status code")
        c_header = resp.headers.get('Set-Cookie', None)
        self.assertIsNotNone(c_header,
                             "Set-Cookie header is missing in the response")
        match = re.search(r'([^;\s]+)=([^;\s]+)', c_header)
        self.assertIsNotNone(match,
                             "Can't extract value from Set-Cookie header")
        new_cookie = (match.group(1), match.group(2))
        self.assertNotEqual(last_cookie, new_cookie,
                            "Challenge is not restarted")

    def process_js_challenge(self, client, host, delay_min, delay_range,
                             status_code, expect_pass, req_delay,
                             restart_on_fail=False):
        """Our tests can't pass the JS challenge with propper configuration,
        enlarge delay limit to not recommended values to make it possible to
        hardcode the JS challenge.
        """
        req = ("GET / HTTP/1.1\r\n"
               "Host: %s\r\n"
               "Accept: text/html\r\n"
               "\r\n" % (host))
        resp = self.client_send_req(client, req)
        self.assertEqual(resp.status, '%d' % status_code,
                         "unexpected response status code")
        c_header = resp.headers.get('Set-Cookie', None)
        self.assertIsNotNone(c_header,
                             "Set-Cookie header is missing in the response")
        match = re.search(r'([^;\s]+)=([^;\s]+)', c_header)
        self.assertIsNotNone(match,
                             "Cant extract value from Set-Cookie header")
        cookie = (match.group(1), match.group(2))

        # Check that all the variables are passed correctly into JS challenge
        # code:
        js_vars = ['var c_name = "%s";' % cookie[0],
                   'var delay_min = %d;' % delay_min,
                   'var delay_range = %d;' % delay_range]
        for js_var in js_vars:
            self.assertIn(js_var, resp.body,
                          "Can't find JS Challenge parameter in response body")

        # Pretend we can eval JS code and pass the challenge, but we can't set
        # reliable timeouts and pass the challenge on CI or in virtual
        # environments. Instead increase the JS parameters to make hardcoding
        # easy and reliable.
        if req_delay:
            time.sleep(req_delay)

        req = ("GET / HTTP/1.1\r\n"
               "Host: %s\r\n"
               "Accept: text/html\r\n"
               "Cookie: %s=%s\r\n"
               "\r\n" % (host, cookie[0], cookie[1]))
        if not expect_pass:
            if restart_on_fail:
                self.expect_restart(client, req, status_code, cookie)
            else:
                self.client_expect_block(client, req)
            return
        resp = self.client_send_req(client, req)
        self.assertEqual(resp.status, '200',
                         "unexpected response status code")

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
            'id' : 'server-1',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' :
            'HTTP/1.1 200 OK\r\n'
            'Content-Length: 0\r\n\r\n'
        },
    ]

    tempesta = {
        'config' :
        """
        server ${server_ip}:8000;

        vhost vh1 {
            proxy_pass default;
            sticky {
                cookie enforce name=cname;
                js_challenge resp_code=503 delay_min=1000 delay_range=1500
                             delay_limit=3000 ${tempesta_workdir}/js1.html;
            }
        }

        vhost vh2 {
            proxy_pass default;
            sticky {
                cookie enforce;
                js_challenge resp_code=302 delay_min=2000 delay_range=1200
                             delay_limit=2000 ${tempesta_workdir}/js2.html;
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
            'id' : 'client-1',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80',
        },
        {
            'id' : 'client-2',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80',
        },
        {
            'id' : 'client-3',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80',
        }
    ]

    def prepare_js_templates(self):
        """
        Templates for JS challenge are modified by start script, create a copy
        of default template for each vhost.
        """
        srcdir = tf_cfg.cfg.get('Tempesta', 'srcdir')
        workdir = tf_cfg.cfg.get('Tempesta', 'workdir')
        template = "%s/etc/js_challenge.tpl" % srcdir
        js_code = "%s/etc/js_challenge.js.tpl" % srcdir
        remote.tempesta.run_cmd("cp %s %s"  % (js_code, workdir))
        remote.tempesta.run_cmd("cp %s %s/js1.tpl" % (template, workdir))
        remote.tempesta.run_cmd("cp %s %s/js2.tpl" % (template, workdir))
        remote.tempesta.run_cmd("cp %s %s/js3.tpl" % (template, workdir))

    def test_get_challenge(self):
        """Not all requests are challengeable. Tempesta sends the challenge
        only if the client can accept it, i.e. request should has GET method and
        'Accept: text/html OR */*'. In other cases normal browsers don't eval
        JS code and TempestaFW is not trying to send the challenge to bots.
        """
        self.start_all()
        client = self.get_client('client-1')

        # Client can accept JS code in responses.
        req = ("GET / HTTP/1.1\r\n"
               "Host: vh1.com\r\n"
               "Accept: text/html\r\n"
               "\r\n")
        resp = self.client_send_req(client, req)
        self.assertEqual(resp.status, '503',
                         "Unexpected response status code")
        self.assertIsNotNone(resp.headers.get('Set-Cookie', None),
                             "Set-Cookie header is missing in the response")
        match = re.search(r'(location\.reload)', resp.body)
        self.assertIsNotNone(match,
                             "Can't extract redirect target from response body")

        req = ("GET / HTTP/1.1\r\n"
               "Host: vh1.com\r\n"
               "Accept: */*\r\n"
               "\r\n")
        self.client_expect_block(client, req)

        # Resource is not challengable, request will be blocked and the
        # connection will be reset.
        req = ("GET / HTTP/1.1\r\n"
               "Host: vh1.com\r\n"
               "Accept: text/plain\r\n"
               "\r\n")
        self.client_expect_block(client, req)

    def test_pass_challenge(self):
        """ Clients send the validating request just in time and pass the
        challenge.
        """
        self.start_all()

        tf_cfg.dbg(3, "Send request to vhost 1 with timeout 2s...")
        client = self.get_client('client-1')
        self.process_js_challenge(client, 'vh1.com',
                                  delay_min=1000, delay_range=1500,
                                  status_code=503, expect_pass=True,
                                  req_delay=2.5)

        tf_cfg.dbg(3, "Send request to vhost 2 with timeout 4s...")
        client = self.get_client('client-2')
        self.process_js_challenge(client, 'vh2.com',
                                  delay_min=2000, delay_range=1200,
                                  status_code=302, expect_pass=True,
                                  req_delay=3.5)
        # Vhost 3 has very strict window to receive the request, skip it in
        # this test.

    def test_fail_challenge_too_early(self):
        """ Clients send the validating request too early, Tempesta closes the
        connection.
        """
        self.start_all()

        tf_cfg.dbg(3, "Send request to vhost 1 with timeout 0s...")
        client = self.get_client('client-1')
        self.process_js_challenge(client, 'vh1.com',
                                  delay_min=1000, delay_range=1500,
                                  status_code=503, expect_pass=False,
                                  req_delay=0)

        tf_cfg.dbg(3, "Send request to vhost 2 with timeout 1s...")
        client = self.get_client('client-2')
        self.process_js_challenge(client, 'vh2.com',
                                  delay_min=2000, delay_range=1200,
                                  status_code=302, expect_pass=False,
                                  req_delay=1)

        tf_cfg.dbg(3, "Send request to vhost 3 with timeout 0s...")
        client = self.get_client('client-3')
        self.process_js_challenge(client, 'vh3.com',
                                  delay_min=1000, delay_range=1000,
                                  status_code=503, expect_pass=False,
                                  req_delay=0)

    def test_fail_challenge_too_late(self):
        """ Clients send the validating request too late, Tempesta restarts
        cookie challenge.
        """
        self.start_all()

        tf_cfg.dbg(3, "Send request to vhost 1 with timeout 6s...")
        client = self.get_client('client-1')
        self.process_js_challenge(client, 'vh1.com',
                                  delay_min=1000, delay_range=1500,
                                  status_code=503, expect_pass=False,
                                  req_delay=6, restart_on_fail=True)

        tf_cfg.dbg(3, "Send request to vhost 2 with timeout 6s...")
        client = self.get_client('client-2')
        self.process_js_challenge(client, 'vh2.com',
                                  delay_min=2000, delay_range=1200,
                                  status_code=302, expect_pass=False,
                                  req_delay=6, restart_on_fail=True)

        tf_cfg.dbg(3, "Send request to vhost 3 with timeout 3s...")
        client = self.get_client('client-3')
        self.process_js_challenge(client, 'vh3.com',
                                  delay_min=1000, delay_range=1000,
                                  status_code=503, expect_pass=False,
                                  req_delay=3, restart_on_fail=True)

class JSChallengeAfterReload(BaseJSChallenge):
    # Test on enable JS Challenge after reload

    backends = [
        {
            'id' : 'server-1',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' :
            'HTTP/1.1 200 OK\r\n'
            'Content-Length: 0\r\n\r\n'
        },
    ]

    tempesta = {
        'config' :
        """
        server ${server_ip}:8000;

        sticky {
            cookie enforce name=cname;
        }
        """
    }

    clients = [
        {
            'id' : 'client-1',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80',
        },
    ]

    def prepare_js_templates(self):
        """
        Templates for JS challenge are modified by start script, create a copy
        of default template for each vhost.
        """
        srcdir = tf_cfg.cfg.get('Tempesta', 'srcdir')
        workdir = tf_cfg.cfg.get('Tempesta', 'workdir')
        template = "%s/etc/js_challenge.tpl" % srcdir
        js_code = "%s/etc/js_challenge.js.tpl" % srcdir
        remote.tempesta.run_cmd("cp %s %s"  % (js_code, workdir))
        remote.tempesta.run_cmd("cp %s %s/js1.tpl" % (template, workdir))

    def test(self):
        """ Clients sends the validating request after reload just in time and
        passes the challenge.
        """
        self.start_all()

        # Reloading Tempesta config with JS challenge enabled
        config = tempesta.Config()
        config.set_defconfig("""
        server %s:8000;

        sticky {
            cookie enforce name=cname;
            js_challenge resp_code=503 delay_min=1000 delay_range=1500
                         delay_limit=3000 %s/js1.html;
        }
        """ % (tf_cfg.cfg.get('Server', 'ip'), tf_cfg.cfg.get('Tempesta', 'workdir')))
        self.get_tempesta().config = config
        self.get_tempesta().reload()

        tf_cfg.dbg(3, "Send request to vhost 1 with timeout 2s...")
        client = self.get_client('client-1')
        self.process_js_challenge(client, 'vh1.com',
                                  delay_min=1000, delay_range=1500,
                                  status_code=503, expect_pass=True,
                                  req_delay=2.5)
