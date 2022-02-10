"""
Basic tests for Tempesta cookies.
"""

import re, time
from helpers import tf_cfg
from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

DFLT_COOKIE_NAME = '__tfw'

class CookiesNotEnabled(tester.TempestaTest):
    """
    Sticky cookies are not enabled on Tempesta, so all clients may access the
    requested resources. No cookie challenge is used to check clients behaviour.
    """

    backends = [
        {
            'id' : 'server-1',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' :
            'HTTP/1.1 200 OK\r\n'
            'Server-id: server-1\r\n'
            'Content-Length: 0\r\n\r\n'
        },
        {
            'id' : 'server-2',
            'type' : 'deproxy',
            'port' : '8001',
            'response' : 'static',
            'response_content' :
            'HTTP/1.1 200 OK\r\n'
            'Server-id: server-2\r\n'
            'Content-Length: 0\r\n\r\n'
        },
        {
            'id' : 'server-3',
            'type' : 'deproxy',
            'port' : '8002',
            'response' : 'static',
            'response_content' :
            'HTTP/1.1 200 OK\r\n'
            'Server-id: server-3\r\n'
            'Content-Length: 0\r\n\r\n'
        },
    ]

    tempesta = {
        'config' :
        """
        server ${server_ip}:8000;
        server ${server_ip}:8001;
        server ${server_ip}:8002;

        """
    }

    clients = [
        {
            'id' : 'client-no-cookies',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80',
            'support_cookies' : False
        },
        {
            'id' : 'client-with-cookies',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80',
            'support_cookies' : True
        },
    ]

    def client_supports_cookies(self, client_name):
        for client in self.clients:
            if client['id'] == client_name:
                return client.get('support_cookies', False)
        return False

    def client_send_req(self, client, req):
        curr_responses = len(client.responses)
        client.make_requests(req)
        client.wait_for_response(timeout=1)
        self.assertEqual(curr_responses + 1, len(client.responses))

        return client.responses[-1]

    def extract_cookie(self, response, cookie_name=None):
        if not cookie_name:
            cookie_name = DFLT_COOKIE_NAME
        # Redirect with sticky cookie, read cookie and make a new request with a cookie
        c_header = response.headers.get('Set-Cookie', None)
        self.assertIsNotNone(c_header,
                             "Set-Cookie header is missing in the response")
        match = re.search(r'%s=([^;\s]+)' % cookie_name, c_header)
        if not match:
            return None
        return (cookie_name, match.group(1))

    def client_get(self, client_name, vhost,
                        cookie_name=None):
        """Make a request and process sticky cookie challenge if required.
        """
        client = self.get_client(client_name)

        req = ("GET / HTTP/1.1\r\n"
               "Host: %s\r\n"
               "\r\n" % vhost)
        response = self.client_send_req(client, req)
        if response.status == '200':
            return True

        if response.status != '302':
            tf_cfg.dbg(3, "Unexpected response code %s" % response.status)
            return False
        if not self.client_supports_cookies(client_name):
            tf_cfg.dbg(3, "Redirect was sent but client don't support cookies")
            return False
        # Tempesta constructs 'Location:' header using host header, current
        # uri and redirect mark. In this test redirect mark is disabled,
        # check that the redirect location is formed correctly.
        location = response.headers['location']
        location_exp = 'http://%s/' % vhost
        self.assertEqual(location, location_exp,
                         "Location header is misformed: expect '%s' got '%s'"
                         % (location_exp, location))

        cookie = self.extract_cookie(response, cookie_name)
        if not cookie:
            return False
        req = ("GET / HTTP/1.1\r\n"
               "Host: %s\r\n"
               "Cookie: %s=%s\r\n"
               "\r\n" % (vhost, cookie[0], cookie[1]))
        response = self.client_send_req(client, req)
        if response.status == '200':
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
        vhost = 'localhost'

        tf_cfg.dbg(3, "Send request from client without cookie support...")
        self.assertTrue(self.client_get('client-no-cookies', vhost),
                        "Client couldn't access resource")

        tf_cfg.dbg(3, "Send request from client with cookie support...")
        self.assertTrue(self.client_get('client-with-cookies', vhost),
                        "Client couldn't access resource")


class CookiesEnabled(CookiesNotEnabled):
    """Implicit 'default' vhost with sticky cookies enabled. Enforce mode of
    cookies is not enabled, so clients can access the resource without cookie
    challenge.
    """

    tempesta = {
        'config' :
        """
        server ${server_ip}:8000;
        server ${server_ip}:8001;
        server ${server_ip}:8002;

        sticky {
            cookie;
        }

        """
    }


class CookiesEnforced(CookiesNotEnabled):
    """Implicit 'default' vhost with sticky cookies enabled. Enforce mode of
    cookies is enabled, so clients can access the resource only after passing
    challenge.
    """

    tempesta = {
        'config' :
        """
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
        vhost = 'localhost'

        tf_cfg.dbg(3, "Send request from client without cookie support...")
        self.assertFalse(self.client_get('client-no-cookies', vhost),
                         "Client accessed resource without cookie challenge")

        tf_cfg.dbg(3, "Send request from client with cookie support...")
        self.assertTrue(self.client_get('client-with-cookies', vhost),
                        "Client couldn't access resource")


class VhostCookies(CookiesNotEnabled):
    """Cookies are configured per-vhost, and clients may get the requested
    resources only if valid cookie name and value is set.
    """

    tempesta = {
        'config' :
        """
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
                cookie name=c_vh1 enforce;
            }
        }

        vhost vh_2 {
            proxy_pass vh_2_srvs;

            sticky {
                cookie name=c_vh2 enforce;
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
        self.assertFalse(self.client_get('client-no-cookies', 'vh1.com'),
                         "Client accessed resource without cookie challenge")
        self.assertFalse(self.client_get('client-with-cookies', 'vh1.com'),
                         "Client accessed resource without cookie challenge")
        # Cookie name from vhost_1, client can pass cookie challenge.
        self.assertFalse(self.client_get('client-no-cookies', 'vh1.com',
                                              cookie_name='c_vh1'),
                         "Client accessed resource without cookie challenge")
        self.assertTrue(self.client_get('client-with-cookies', 'vh1.com',
                                             cookie_name='c_vh1'),
                        "Client couldn't access resource")
        # Cookie name from vhost_2, client can't pass cookie challenge.
        self.assertFalse(self.client_get('client-no-cookies', 'vh1.com',
                                              cookie_name='c_vh2'),
                         "Client accessed resource without cookie challenge")
        self.assertFalse(self.client_get('client-with-cookies', 'vh1.com',
                                              cookie_name='c_vh2'),
                         "Client accessed resource without cookie challenge")
        # Cookie name from vhost_3, client can't pass cookie challenge.
        self.assertFalse(self.client_get('client-no-cookies', 'vh1.com',
                                              cookie_name='c_vh3'),
                         "Client accessed resource without cookie challenge")
        self.assertFalse(self.client_get('client-with-cookies', 'vh1.com',
                                              cookie_name='c_vh3'),
                         "Client accessed resource without cookie challenge")

        tf_cfg.dbg(3, "Send requests to vhost_2...")
        # Default cookie name is used, client can't pass cookie challenge.
        self.assertFalse(self.client_get('client-no-cookies', 'vh2.com'),
                         "Client accessed resource without cookie challenge")
        self.assertFalse(self.client_get('client-with-cookies', 'vh2.com'),
                         "Client accessed resource without cookie challenge")
        # Cookie name from vhost_1, client can't pass cookie challenge.
        self.assertFalse(self.client_get('client-no-cookies', 'vh2.com',
                                              cookie_name='c_vh1'),
                         "Client accessed resource without cookie challenge")
        self.assertFalse(self.client_get('client-with-cookies', 'vh2.com',
                                              cookie_name='c_vh1'),
                         "Client accessed resource without cookie challenge")
        # Cookie name from vhost_2, client can't pass cookie challenge.
        self.assertFalse(self.client_get('client-no-cookies', 'vh2.com',
                                              cookie_name='c_vh2'),
                         "Client accessed resource without cookie challenge")
        self.assertTrue(self.client_get('client-with-cookies', 'vh2.com',
                                             cookie_name='c_vh2'),
                        "Client couldn't access resource")
        # Cookie name from vhost_3, client can't pass cookie challenge.
        self.assertFalse(self.client_get('client-no-cookies', 'vh2.com',
                                              cookie_name='c_vh3'),
                         "Client accessed resource without cookie challenge")
        self.assertFalse(self.client_get('client-with-cookies', 'vh2.com',
                                              cookie_name='c_vh3'),
                         "Client accessed resource without cookie challenge")

        tf_cfg.dbg(3, "Send requests to vhost_3...")
        # Enforce mode is disabled for vhost_3, cookie challenge is not required
        self.assertTrue(self.client_get('client-no-cookies', 'vh3.com'),
                        "Client couldn't access resource")
        self.assertTrue(self.client_get('client-with-cookies', 'vh3.com',
                                             cookie_name='c_vh3'),
                        "Client couldn't access resource")


class CookiesInherit(VhostCookies):
    """Cookies configuration can be inherited from global defaults. The test is
    identical to VhostCookies. But here 'sticky' directive is defined outside
    named vhosts, so updates default settings that must be inherited by
    named vhosts. If default settings are inherited multiple times, then only
    the last one is effective.
    """

    tempesta = {
        'config' :
        """
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
            cookie name=c_vh1 enforce;
        }

        vhost vh_1 {
            proxy_pass vh_1_srvs;
        }

        sticky {
            cookie name=c_vh2 enforce;
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
        'config' :
        """
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
        client = self.get_client('client-with-cookies')

        req = ("GET / HTTP/1.1\r\n"
               "Host: localhost\r\n"
               "\r\n")
        response = self.client_send_req(client, req)
        self.assertEqual(response.status, '302',
                         ("Unexpected redirect status code: %s, expected 302"
                          % response.status))
        cookie = self.extract_cookie(response)
        self.assertIsNotNone(cookie, "Can't find cookie in response")
        req = ("GET / HTTP/1.1\r\n"
               "Host: localhost\r\n"
               "Cookie: %s=%s\r\n"
               "\r\n" % (cookie[0], cookie[1]))
        response = self.client_send_req(client, req)
        self.assertEqual(response.status, '200',
                         ("Unexpected redirect status code: %s, expected 200"
                          % response.status))
        # Cookies are enforced, only the first response (redirect) has
        # Set-Cookie header, following responses has no such header.
        self.assertIsNone(response.headers.get('Set-Cookie', None),
                          "Set-Cookie header is mistakenly set in the response")
        tf_cfg.dbg(3, "Sleep until session get expired...")
        time.sleep(5)
        req = ("GET / HTTP/1.1\r\n"
               "Host: localhost\r\n"
               "Cookie: %s=%s\r\n"
               "\r\n" % (cookie[0], cookie[1]))
        response = self.client_send_req(client, req)
        self.assertEqual(response.status, '302',
                         "Unexpected redirect status code")
