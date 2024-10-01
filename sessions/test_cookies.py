"""
Basic tests for Tempesta cookies.
"""

import re
import time

from framework.parameterize import param, parameterize, parameterize_class
from helpers import dmesg, remote, tf_cfg
from helpers.remote import CmdError
from test_suite import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2019-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

DFLT_COOKIE_NAME = "__tfw"


class CookiesNotEnabled(tester.TempestaTest):
    """
    Sticky cookies are not enabled on Tempesta, so all clients may access the
    requested resources. No cookie challenge is used to check clients behaviour.
    """

    backends = [
        {
            "id": "server-1",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Server-id: server-1\r\n"
            "Content-Length: 0\r\n\r\n",
        },
        {
            "id": "server-2",
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Server-id: server-2\r\n"
            "Content-Length: 0\r\n\r\n",
        },
        {
            "id": "server-3",
            "type": "deproxy",
            "port": "8002",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Server-id: server-3\r\n"
            "Content-Length: 0\r\n\r\n",
        },
    ]

    tempesta = {
        "config": """
        server ${server_ip}:8000;
        server ${server_ip}:8001;
        server ${server_ip}:8002;

        """
    }

    clients = [
        {
            "id": "client-no-cookies",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
            "support_cookies": False,
        },
        {
            "id": "client-with-cookies",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
            "support_cookies": True,
        },
    ]

    def client_supports_cookies(self, client_name):
        for client in self.clients:
            if client["id"] == client_name:
                return client.get("support_cookies", False)
        return False

    def client_send_req(self, client, req):
        curr_responses = len(client.responses)
        client.make_request(req)
        client.wait_for_response(timeout=1)
        self.assertEqual(curr_responses + 1, len(client.responses))

        return client.responses[-1]

    def extract_cookie(self, response, cookie_name=None):
        if not cookie_name:
            cookie_name = DFLT_COOKIE_NAME
        # Redirect with sticky cookie, read cookie and make a new request with a cookie
        c_header = response.headers.get("Set-Cookie", None)
        self.assertIsNotNone(c_header, "Set-Cookie header is missing in the response")
        match = re.search(r"%s=([^;\s]+)" % cookie_name, c_header)
        if not match:
            return None
        return (cookie_name, match.group(1))

    def client_get(self, client_name, vhost, cookie_name=None):
        """Make a request and process sticky cookie challenge if required."""
        client = self.get_client(client_name)

        req = "GET / HTTP/1.1\r\n" "Host: %s\r\n" "\r\n" % vhost
        response = self.client_send_req(client, req)
        if response.status == "200":
            return True

        if response.status != "302":
            tf_cfg.dbg(3, "Unexpected response code %s" % response.status)
            return False
        if not self.client_supports_cookies(client_name):
            tf_cfg.dbg(3, "Redirect was sent but client don't support cookies")
            return False
        # Tempesta constructs 'Location:' header using host header, current
        # uri and redirect mark. In this test redirect mark is disabled,
        # check that the redirect location is formed correctly.
        location = response.headers["location"]
        location_exp = "http://%s/" % vhost
        self.assertEqual(
            location,
            location_exp,
            "Location header is misformed: expect '%s' got '%s'" % (location_exp, location),
        )

        cookie = self.extract_cookie(response, cookie_name)
        if not cookie:
            return False
        req = (
            "GET / HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Cookie: %s=%s\r\n"
            "\r\n" % (vhost, cookie[0], cookie[1])
        )
        response = self.client_send_req(client, req)
        if response.status == "200":
            return True

        return False

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections(1))

    def test_cookie(self):
        self.start_all()
        vhost = "localhost"

        tf_cfg.dbg(3, "Send request from client without cookie support...")
        self.assertTrue(
            self.client_get("client-no-cookies", vhost), "Client couldn't access resource"
        )

        tf_cfg.dbg(3, "Send request from client with cookie support...")
        self.assertTrue(
            self.client_get("client-with-cookies", vhost), "Client couldn't access resource"
        )


class CookiesEnabled(CookiesNotEnabled):
    """Implicit 'default' vhost with sticky cookies enabled. Enforce mode of
    cookies is not enabled, so clients can access the resource without cookie
    challenge.
    """

    tempesta = {
        "config": """
        server ${server_ip}:8000;
        server ${server_ip}:8001;
        server ${server_ip}:8002;

        sticky {
            cookie;
        }

        """
    }

    def test_cookie(self):
        self.disable_deproxy_auto_parser()
        super().test_cookie()


class CookiesEnforced(CookiesNotEnabled):
    """Implicit 'default' vhost with sticky cookies enabled. Enforce mode of
    cookies is enabled, so clients can access the resource only after passing
    challenge.
    """

    tempesta = {
        "config": """
        server ${server_ip}:8000;
        server ${server_ip}:8001;
        server ${server_ip}:8002;

        sticky {
            cookie enforce;
        }

        """
    }

    def test_cookie(self):
        self.start_all()
        vhost = "localhost"

        tf_cfg.dbg(3, "Send request from client without cookie support...")
        self.assertFalse(
            self.client_get("client-no-cookies", vhost),
            "Client accessed resource without cookie challenge",
        )

        tf_cfg.dbg(3, "Send request from client with cookie support...")
        self.assertTrue(
            self.client_get("client-with-cookies", vhost), "Client couldn't access resource"
        )


class CookiesMaxMisses(tester.TempestaTest):
    max_misses = 2
    tempesta = {
        "config": f"""
        server ${{server_ip}}:8000;

        block_action attack reply;
        block_action error reply;

        sticky {{
            cookie enforce max_misses={max_misses};
        }}

        """
    }

    clients = [
        {
            "id": "client",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        }
    ]

    backends = [
        {
            "id": "server",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Server-id: deproxy\r\n"
            "Content-Length: 0\r\n\r\n",
        }
    ]

    @parameterize.expand(
        [
            param(name="no_cookie", headers=[]),
            param(name="with_invalid_cookie", headers=[("cookie", "__tfw=0000db26d9f76f8c40ba5c")]),
        ]
    )
    def test_max_misses_(self, name, headers):
        """
        Tempesta MUST close connection when requests of client does not contain cookie
        (or contain invalid cookie) and the number of requests greater than max_misses.
        """
        self.start_all_services()

        client = self.get_client("client")
        request = client.create_request(method="GET", headers=headers)

        for _ in range(self.max_misses + 1):
            client.send_request(request)

        self.assertEqual(client.last_response.status, "403")
        self.assertTrue(client.wait_for_connection_close())


class VhostCookies(CookiesNotEnabled):
    """Cookies are configured per-vhost, and clients may get the requested
    resources only if valid cookie name and value is set.
    """

    tempesta = {
        "config": """
        srv_group vh_1_srvs {
            server ${server_ip}:8000;
        }
        srv_group vh_2_srvs {
            server ${server_ip}:8001;
        }
        srv_group vh_3_srvs {
            server ${server_ip}:8002;
        }

        vhost vh_1 {
            proxy_pass vh_1_srvs;

            sticky {
                cookie name=c_vh1 enforce max_misses=0;
            }
        }

        vhost vh_2 {
            proxy_pass vh_2_srvs;

            sticky {
                cookie name=c_vh2 enforce max_misses=0;
            }
        }

        vhost vh_3 {
            proxy_pass vh_3_srvs;

            sticky {
                cookie name=c_vh3;
            }
        }

        http_chain {
            host == "vh1.com" -> vh_1;
            host == "vh2.com" -> vh_2;
            host == "vh3.com" -> vh_3;
            -> block;
        }

        """
    }

    def test_cookie(self):
        self.start_all()

        tf_cfg.dbg(3, "Send requests to vhost_1...")
        # Default cookie name is used, client can't pass cookie challenge.
        self.assertFalse(
            self.client_get("client-no-cookies", "vh1.com"),
            "Client accessed resource without cookie challenge",
        )
        self.assertFalse(
            self.client_get("client-with-cookies", "vh1.com"),
            "Client accessed resource without cookie challenge",
        )
        # Cookie name from vhost_1, client can pass cookie challenge.
        self.assertFalse(
            self.client_get("client-no-cookies", "vh1.com", cookie_name="c_vh1"),
            "Client accessed resource without cookie challenge",
        )
        self.assertTrue(
            self.client_get("client-with-cookies", "vh1.com", cookie_name="c_vh1"),
            "Client couldn't access resource",
        )
        # Cookie name from vhost_2, client can't pass cookie challenge.
        self.assertFalse(
            self.client_get("client-no-cookies", "vh1.com", cookie_name="c_vh2"),
            "Client accessed resource without cookie challenge",
        )
        self.assertFalse(
            self.client_get("client-with-cookies", "vh1.com", cookie_name="c_vh2"),
            "Client accessed resource without cookie challenge",
        )
        # Cookie name from vhost_3, client can't pass cookie challenge.
        self.assertFalse(
            self.client_get("client-no-cookies", "vh1.com", cookie_name="c_vh3"),
            "Client accessed resource without cookie challenge",
        )
        self.assertFalse(
            self.client_get("client-with-cookies", "vh1.com", cookie_name="c_vh3"),
            "Client accessed resource without cookie challenge",
        )

        tf_cfg.dbg(3, "Send requests to vhost_2...")
        # Default cookie name is used, client can't pass cookie challenge.
        self.assertFalse(
            self.client_get("client-no-cookies", "vh2.com"),
            "Client accessed resource without cookie challenge",
        )
        self.assertFalse(
            self.client_get("client-with-cookies", "vh2.com"),
            "Client accessed resource without cookie challenge",
        )
        # Cookie name from vhost_1, client can't pass cookie challenge.
        self.assertFalse(
            self.client_get("client-no-cookies", "vh2.com", cookie_name="c_vh1"),
            "Client accessed resource without cookie challenge",
        )
        self.assertFalse(
            self.client_get("client-with-cookies", "vh2.com", cookie_name="c_vh1"),
            "Client accessed resource without cookie challenge",
        )
        # Cookie name from vhost_2, client can't pass cookie challenge.
        self.assertFalse(
            self.client_get("client-no-cookies", "vh2.com", cookie_name="c_vh2"),
            "Client accessed resource without cookie challenge",
        )
        self.assertTrue(
            self.client_get("client-with-cookies", "vh2.com", cookie_name="c_vh2"),
            "Client couldn't access resource",
        )
        # Cookie name from vhost_3, client can't pass cookie challenge.
        self.assertFalse(
            self.client_get("client-no-cookies", "vh2.com", cookie_name="c_vh3"),
            "Client accessed resource without cookie challenge",
        )
        self.assertFalse(
            self.client_get("client-with-cookies", "vh2.com", cookie_name="c_vh3"),
            "Client accessed resource without cookie challenge",
        )

        self.disable_deproxy_auto_parser()
        tf_cfg.dbg(3, "Send requests to vhost_3...")
        # Enforce mode is disabled for vhost_3, cookie challenge is not required
        self.assertTrue(
            self.client_get("client-no-cookies", "vh3.com"), "Client couldn't access resource"
        )
        self.assertTrue(
            self.client_get("client-with-cookies", "vh3.com", cookie_name="c_vh3"),
            "Client couldn't access resource",
        )


class CookiesInherit(VhostCookies):
    """Cookies configuration can be inherited from global defaults. The test is
    identical to VhostCookies. But here 'sticky' directive is defined outside
    named vhosts, so updates default settings that must be inherited by
    named vhosts. If default settings are inherited multiple times, then only
    the last one is effective.
    """

    tempesta = {
        "config": """
        srv_group vh_1_srvs {
            server ${server_ip}:8000;
        }
        srv_group vh_2_srvs {
            server ${server_ip}:8001;
        }
        srv_group vh_3_srvs {
            server ${server_ip}:8002;
        }

        sticky {
            cookie name=c_vh1 enforce max_misses=0;
        }

        vhost vh_1 {
            proxy_pass vh_1_srvs;
        }

        sticky {
            cookie name=c_vh2 enforce max_misses=0;
        }

        vhost vh_2 {
            proxy_pass vh_2_srvs;
        }

        sticky {
            cookie name=not_used;
        }

        sticky {
            cookie name=c_vh3;
        }

        vhost vh_3 {
            proxy_pass vh_3_srvs;
        }

        http_chain {
            host == "vh1.com" -> vh_1;
            host == "vh2.com" -> vh_2;
            host == "vh3.com" -> vh_3;
            -> block;
        }

        """
    }


class CookieLifetime(CookiesNotEnabled):
    tempesta = {
        "config": """
        server ${server_ip}:8000;
        server ${server_ip}:8001;
        server ${server_ip}:8002;

        sticky {
            cookie enforce;
            sess_lifetime 2;
        }

        """
    }

    def test_cookie(self):
        self.start_all()
        client = self.get_client("client-with-cookies")

        req = "GET / HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        response = self.client_send_req(client, req)
        self.assertEqual(
            response.status,
            "302",
            ("Unexpected redirect status code: %s, expected 302" % response.status),
        )
        cookie = self.extract_cookie(response)
        self.assertIsNotNone(cookie, "Can't find cookie in response")
        req = (
            "GET / HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Cookie: %s=%s\r\n"
            "\r\n" % (cookie[0], cookie[1])
        )
        response = self.client_send_req(client, req)
        self.assertEqual(
            response.status,
            "200",
            ("Unexpected redirect status code: %s, expected 200" % response.status),
        )
        # Cookies are enforced, only the first response (redirect) has
        # Set-Cookie header, following responses has no such header.
        self.assertIsNone(
            response.headers.get("Set-Cookie", None),
            "Set-Cookie header is mistakenly set in the response",
        )
        tf_cfg.dbg(3, "Sleep until session get expired...")
        time.sleep(5)
        req = (
            "GET / HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Cookie: %s=%s\r\n"
            "\r\n" % (cookie[0], cookie[1])
        )
        response = self.client_send_req(client, req)
        self.assertEqual(response.status, "302", "Unexpected redirect status code")


GLOBAL_TEMPLATE = {
    "config": """
sticky {
    %s
}
"""
}

VHOST_TEMPLATE = {
    "config": """
srv_group default {
    server ${server_ip}:8000;
}

vhost example.com {
    sticky {
        %s
    }

    proxy_pass default;
}
"""
}


@parameterize_class(
    [
        {"name": "Global", "tempesta": GLOBAL_TEMPLATE},
        {"name": "Vhost", "tempesta": VHOST_TEMPLATE},
    ]
)
class StickyCookieConfig(tester.TempestaTest):
    @dmesg.unlimited_rate_on_tempesta_node
    def check_cannot_start_impl(self, msg):
        self.oops_ignore = ["WARNING", "ERROR"]
        with self.assertRaises(CmdError, msg=""):
            self.start_tempesta()
        self.assertTrue(
            self.oops.find(msg, cond=dmesg.amount_positive), "Tempesta doesn't report error"
        )

    def setUp(self):
        super().setUp()
        srcdir = tf_cfg.cfg.get("Tempesta", "srcdir")
        workdir = tf_cfg.cfg.get("Tempesta", "workdir")
        remote.tempesta.run_cmd(f"cp {srcdir}/etc/js_challenge.js.tpl {workdir}")
        remote.tempesta.run_cmd(f"cp {srcdir}/etc/js_challenge.tpl {workdir}/js1.tpl")

    @parameterize.expand(
        [
            param(
                name="cookie_options_no_cookie",
                cookie_config="cookie_options Path=/;",
                msg="http_sess: cookie options requires sticky cookies enabled and explicitly defined in the same section",
            ),
            param(
                name="js_challenge_no_cookie",
                cookie_config="js_challenge resp_code=503 delay_min=1000 delay_range=3000 %s/js1.html;"
                % tf_cfg.cfg.get("Tempesta", "workdir"),
                msg="http_sess: JavaScript challenge requires sticky cookies enabled and explicitly defined in the same section",
            ),
            param(
                name="empty_js_challenge",
                cookie_config="js_challenge;\ncookie enforce;",
                msg="js_challenge: required argument 'delay_min' not set",
            ),
            param(
                name="cookie_options_with_cookie",
                cookie_config="cookie_options Path=/;\ncookie enforce;",
                msg=None,
            ),
            param(
                name="js_challenge_with_cookie",
                cookie_config="js_challenge resp_code=503 delay_min=1000 delay_range=3000 %s/js1.html;\ncookie enforce;"
                % tf_cfg.cfg.get("Tempesta", "workdir"),
                msg=None,
            ),
            param(
                name="dublicate_delay_min",
                cookie_config="js_challenge resp_code=503 delay_min=1000 delay_min=2000 delay_range=3000 %s/js1.html;\ncookie enforce;"
                % tf_cfg.cfg.get("Tempesta", "workdir"),
                msg="Duplicate argument: 'delay_min'",
            ),
            param(
                name="dublicate_delay_range",
                cookie_config="js_challenge resp_code=503 delay_min=1000 delay_range=2000 delay_range=3000 %s/js1.html;\ncookie enforce;"
                % tf_cfg.cfg.get("Tempesta", "workdir"),
                msg="Duplicate argument: 'delay_range'",
            ),
            param(
                name="dublicate_resp_code",
                cookie_config="js_challenge resp_code=503 resp_code=502 delay_min=2000 delay_range=3000 %s/js1.html;\ncookie enforce;"
                % tf_cfg.cfg.get("Tempesta", "workdir"),
                msg="Duplicate argument: 'resp_code'",
            ),
            param(
                name="dublicate_name",
                cookie_config="cookie name=A name=B enforce;",
                msg="Duplicate argument: 'name'",
            ),
            param(
                name="dublicate_max_misses",
                cookie_config="cookie max_misses=3 max_misses=4 enforce;",
                msg="Duplicate argument: 'max_misses'",
            ),
        ]
    )
    def test(self, name, cookie_config, msg):
        tempesta_conf = self.get_tempesta().config

        tempesta_conf.set_defconfig(tempesta_conf.defconfig % cookie_config)
        if msg is not None:
            self.check_cannot_start_impl(msg)
        else:
            self.start_all_services()


class StickyCookieOptions(tester.TempestaTest):
    clients = [{"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"}]

    tempesta = {
        "config": """
        srv_group default {
            server ${server_ip}:8000;
        }
        srv_group example {
            server ${server_ip}:8001;
        }

        sticky {
            cookie enforce max_misses=10;
            %s
        }

        vhost default {
            proxy_pass default;
        }

        vhost example.com {
            sticky {
                cookie enforce max_misses=2;
                %s
            }

            proxy_pass example;
        }

        http_chain {
            host == "example.com" -> example.com;
            -> default;
        }
        """
    }

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        }
    ]

    @dmesg.unlimited_rate_on_tempesta_node
    def check_cannot_start_impl(self, msg):
        self.oops_ignore = ["WARNING", "ERROR"]
        with self.assertRaises(CmdError, msg=""):
            self.start_tempesta()
        self.assertTrue(
            self.oops.find(msg, cond=dmesg.amount_positive), "Tempesta doesn't report error"
        )

    @parameterize.expand(
        [
            # If no options are set, session lifetime is equal to UINT_MAX (4294967295)
            # and Max-Age is set to 4294967295 also. Path is not set, default Path="/"
            # is used.
            param(
                name="empty_options",
                cookie_options_global="",
                cookie_options_vhost="",
                options_global_in_response=["Path=/", "Max-Age=4294967295"],
                options_vhost_in_response=["Path=/", "Max-Age=4294967295"],
            ),
            # Same as previous but cookie_options is in config without any
            # values.
            param(
                name="empty_options_1",
                cookie_options_global="cookie_options;",
                cookie_options_vhost="cookie_options;",
                options_global_in_response=["Path=/", "Max-Age=4294967295"],
                options_vhost_in_response=["Path=/", "Max-Age=4294967295"],
            ),
            # Global session lifetime is set and vhost session lifetime is
            # empty. Global session lifetime is used to set Max-Age for global
            # and vhost cookies.
            param(
                name="empty_vhost_global_sess_lifetime_is_set",
                cookie_options_global="sess_lifetime 5;",
                cookie_options_vhost="",
                options_global_in_response=["Path=/", "Max-Age=5"],
                options_vhost_in_response=["Path=/", "Max-Age=5"],
            ),
            # Global Expires is set, global session lifetime doesn't affect global
            # cookie options, but vhost cookie options are empty, so global session
            # lifetime is used to set Max-Age for vhost cookies.
            param(
                name="empty_vhost_global_expires_and_sess_lifetime_are_set",
                cookie_options_global="cookie_options Path=/etc Expires=111;\nsess_lifetime 5;",
                cookie_options_vhost="",
                options_global_in_response=["Path=/etc", "Expires=111"],
                options_vhost_in_response=["Path=/", "Max-Age=5"],
            ),
            # Global Max-Age is set, session lifetime doesn't  affect global cookie
            # options. Vhost session lifetime is set and used to set vhost cookies
            # Max-Age.
            param(
                name="vhost_sess_lifetime_and_global_sess_lifetime_and_max_age_are_set",
                cookie_options_global="cookie_options Max-Age=111;\nsess_lifetime 5;",
                cookie_options_vhost="sess_lifetime 3;",
                options_global_in_response=["Path=/", "Max-Age=111"],
                options_vhost_in_response=["Path=/", "Max-Age=3"],
            ),
            # Secure option is set, Path and Max-Age are set according to
            # default values ("/" for Path and 4294967295 for Max-Age).
            param(
                name="vhost_and_global_options_other",
                cookie_options_global="cookie_options Secure;",
                cookie_options_vhost="cookie_options Secure;",
                options_global_in_response=["Secure", "Path=/", "Max-Age=4294967295"],
                options_vhost_in_response=["Secure", "Path=/", "Max-Age=4294967295"],
            ),
            # Vhost Expires is set, global session lifetime doesn't affect
            # vhost cookie options.
            param(
                name="vhost_expires_is_set",
                cookie_options_global="sess_lifetime 5;",
                cookie_options_vhost="cookie_options Expires=111;",
                options_global_in_response=["Path=/", "Max-Age=5"],
                options_vhost_in_response=["Path=/", "Expires=111"],
            ),
            # Vhost Max-Age is set, global session lifetime doesn't affect
            # vhost cookie options.
            param(
                name="vhost_max_age_is_set",
                cookie_options_global="sess_lifetime 5;",
                cookie_options_vhost="cookie_options Max-Age=111;",
                options_global_in_response=["Path=/", "Max-Age=5"],
                options_vhost_in_response=["Path=/", "Max-Age=111"],
            ),
            # A lot of different options
            param(
                name="cookie_options_all_in_one",
                cookie_options_global="cookie_options Max-Age=111 Expires=3 Path=/etc Secure HttpOnly Domain=example.com;",
                cookie_options_vhost="",
                options_global_in_response=[
                    "Max-Age=111",
                    "Expires=3",
                    "Path=/etc",
                    "Secure",
                    "HttpOnly",
                    "Domain=example.com",
                ],
                options_vhost_in_response=["Max-Age=4294967295", "Path=/"],
            ),
        ]
    )
    def test(
        self,
        name,
        cookie_options_global,
        cookie_options_vhost,
        options_global_in_response,
        options_vhost_in_response,
    ):
        """
        Send two request, first request to default vhost with global cookies and
        second request to example.com with special cookies. Check Set-Cookie
        header - Tempesta FW should set Path and Max-Age or Expires.
        """
        tempesta_conf = self.get_tempesta().config

        tempesta_conf.set_defconfig(
            tempesta_conf.defconfig % (cookie_options_global, cookie_options_vhost)
        )
        self.start_all_services()

        client = self.get_client("deproxy")
        client.send_request(client.create_request(method="GET", headers=[]), "302")
        set_cookie = client.last_response.headers.get("Set-Cookie", None)
        cookie_opt = set_cookie.split("; ")
        for opt in options_global_in_response:
            self.assertIn(opt, cookie_opt)
        for opt in cookie_opt[1:]:
            self.assertIn(opt, options_global_in_response)

        client.send_request(
            client.create_request(method="GET", authority="example.com", headers=[]), "302"
        )
        set_cookie = client.last_response.headers.get("Set-Cookie", None)
        cookie_opt = set_cookie.split("; ")
        for opt in options_vhost_in_response:
            self.assertIn(opt, cookie_opt)
        for opt in cookie_opt[1:]:
            self.assertIn(opt, options_vhost_in_response)

    @parameterize.expand(
        [
            param(
                name="path",
                options="cookie_options Path=/ Path=/etc;",
                msg="Duplicate argument: 'Path'",
            ),
            param(
                name="max_age",
                options="cookie_options Max-Age=3 Max-Age=5;",
                msg="Duplicate argument: 'Max-Age'",
            ),
            param(
                name="expires",
                options="cookie_options Expires=3 Expires=5;",
                msg="Duplicate argument: 'Expires'",
            ),
        ]
    )
    def test_dublicate(self, name, options, msg):
        tempesta_conf = self.get_tempesta().config

        tempesta_conf.set_defconfig(tempesta_conf.defconfig % (options, "cookie_options;"))
        self.check_cannot_start_impl(msg)
