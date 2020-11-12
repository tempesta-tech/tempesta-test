"""
Redirection marks tests.
"""

import random
import re, time
import string
from helpers import tf_cfg
from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

DFLT_COOKIE_NAME = '__tfw'

class BaseRedirectMark(tester.TempestaTest):

    backends = [
        {
            'id' : 'server',
            'type' : 'deproxy',
            'port' : '8000',
            'response' : 'static',
            'response_content' :
            'HTTP/1.1 200 OK\r\n'
            'Content-Length: 0\r\n\r\n'
        }
    ]

    clients = [
        {
            'id' : 'deproxy',
            'type' : 'deproxy',
            'addr' : "${tempesta_ip}",
            'port' : '80',
        }
    ]

    def wait_all_connections(self, tmt=1):
        srv = self.get_server('server')
        if not srv.wait_for_connections(timeout=tmt):
            return False
        return True

    def client_expect_block(self, client, req):
        curr_responses = len(client.responses)
        client.make_requests(req)
        client.wait_for_response(timeout=2)
        self.assertEqual(curr_responses, len(client.responses))
        self.assertTrue(client.connection_is_closed())

    def client_send_req(self, client, req):
        curr_responses = len(client.responses)
        client.make_requests(req)
        client.wait_for_response(timeout=1)
        self.assertEqual(curr_responses + 1, len(client.responses))

        return client.responses[-1]

    def client_send_custom_req(self, client, uri, cookie):
        req = ("GET %s HTTP/1.1\r\n"
               "Host: localhost\r\n"
               "%s"
               "\r\n" % (uri, ("Cookie: %s=%s\r\n" % cookie) if cookie else ""))
        response = self.client_send_req(client, req)

        self.assertEqual(response.status,'302',
                         "unexpected response status code")
        c_header = response.headers.get('Set-Cookie', None)
        self.assertIsNotNone(c_header,
                             "Set-Cookie header is missing in the response")
        match = re.search(r'([^;\s]+)=([^;\s]+)', c_header)
        self.assertIsNotNone(match,
                             "Cant extract value from Set-Cookie header")
        cookie = (match.group(1), match.group(2))

        # Checking default path option of cookies
        match = re.search(r'path=([^;\s]+)', c_header)
        self.assertIsNotNone(match,
                             "Cant extract path from Set-Cookie header")
        self.assertEqual(match.group(1), "/")

        uri = response.headers.get('Location', None)
        self.assertIsNotNone(uri,
                             "Location header is missing in the response")
        return (uri, cookie)

    def client_send_first_req(self, client, uri):
        return self.client_send_custom_req(client, uri, None)

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections(1))

class RedirectMark(BaseRedirectMark):
    """
    Sticky cookies are not enabled on Tempesta, so all clients may access the
    requested resources. No cookie challenge is used to check clients behaviour.
    """

    tempesta = {
        'config' :
        """
        server ${server_ip}:8000;

        sticky {
            cookie enforce max_misses=5;
        }
        """
    }

    def test_good_rmark_value(self):
        """Client fully process the challenge: redirect is followed correctly,
        cookie is set correctly, so the client can get the requested resources.
        """
        self.start_all()

        client = self.get_client('deproxy')
        uri = '/'
        uri, cookie = self.client_send_first_req(client, uri)
        uri, _ = self.client_send_custom_req(client, uri, cookie)
        hostname = tf_cfg.cfg.get('Tempesta', 'hostname')
        self.assertEqual(uri, 'http://%s/' % hostname)

        req = ("GET %s HTTP/1.1\r\n"
               "Host: localhost\r\n"
               "Cookie: %s=%s\r\n"
               "\r\n" % (uri, cookie[0], cookie[1]))
        response = self.client_send_req(client, req)
        self.assertEqual(response.status,'200',
                         "unexpected response status code")

    def test_rmark_wo_or_incorrect_cookie(self):
        """
        A client sending more than 5 requests without cookies or incorrect
        cookies is blocked. For example a bot which can follow redirects, but
        can't set cookies, must be blocked after 5 attempts.
        """
        self.start_all()

        client = self.get_client('deproxy')
        uri = '/'
        uri, cookie = self.client_send_first_req(client, uri)
        cookie = (cookie[0],
                  ''.join(random.choice(string.hexdigits)
                          for i in range(len(cookie[1]))))
        uri, _ = self.client_send_custom_req(client, uri, cookie)
        uri, cookie = self.client_send_first_req(client, uri)
        cookie = (cookie[0],
                  ''.join(random.choice(string.hexdigits)
                          for i in range(len(cookie[1]))))
        uri, _ = self.client_send_custom_req(client, uri, cookie)
        uri, _ = self.client_send_first_req(client, uri)

        req = ("GET %s HTTP/1.1\r\n"
               "Host: localhost\r\n"
               "\r\n" % uri)
        self.client_expect_block(client, req)

    def test_rmark_invalid(self):
        # Requests w/ incorrect rmark and w/o cookies, must be blocked
        self.start_all()

        client = self.get_client('deproxy')
        uri = '/'
        uri, _ = self.client_send_first_req(client, uri)
        m = re.match(r"(.*=)([0-9a-f]*)(/)", uri)

        req = ("GET %s HTTP/1.1\r\n"
               "Host: localhost\r\n"
               "\r\n" % (m.group(1) +
                         ''.join(random.choice(string.hexdigits)
                         for i in range(len(m.group(2)))) +
                         m.group(3)))
        self.client_expect_block(client, req)


class RedirectMarkVhost(RedirectMark):
    """ Same as RedirectMark, but , but 'sticky' configuration is inherited from
    updated defaults for a named vhost.
    """

    tempesta = {
        'config' :
        """
        srv_group vh_1_srvs {
            server ${server_ip}:8000;
        }

        # Update defaults two times, only the last one must be applied.
        sticky {
            cookie name=c_vh2 enforce;
        }
        sticky {
            cookie enforce max_misses=5;
        }

        vhost vh_1 {
            proxy_pass vh_1_srvs;
        }

        http_chain {
            -> vh_1;
        }
        """
    }


class RedirectMarkTimeout(BaseRedirectMark):
    """
    Current count of redirected requests should be reset if time has
    passed more than timeout cookie option.
    """

    tempesta = {
        'config' :
        """
        server ${server_ip}:8000;

        sticky {
            cookie enforce max_misses=5 timeout=2;
        }
        """
    }

    def test(self):
        self.start_all()

        client = self.get_client('deproxy')
        uri = '/'
        uri, _ = self.client_send_first_req(client, uri)
        uri, _ = self.client_send_first_req(client, uri)
        uri, _ = self.client_send_first_req(client, uri)
        uri, _ = self.client_send_first_req(client, uri)
        uri, _ = self.client_send_first_req(client, uri)

        tf_cfg.dbg(3, "Sleep until cookie timeout get expired...")
        time.sleep(3)

        uri, cookie = self.client_send_first_req(client, uri)
        uri, _ = self.client_send_custom_req(client, uri, cookie)
        hostname = tf_cfg.cfg.get('Tempesta', 'hostname')
        self.assertEqual(uri, 'http://%s/' % hostname)

        req = ("GET %s HTTP/1.1\r\n"
               "Host: localhost\r\n"
               "Cookie: %s=%s\r\n"
               "\r\n" % (uri, cookie[0], cookie[1]))
        response = self.client_send_req(client, req)
        self.assertEqual(response.status,'200',
                         "unexpected response status code")


class RedirectMarkTimeoutVhost(RedirectMarkTimeout):
    """ Same as RedirectMarkTimeout, but , but 'sticky' configuration is
    inherited from updated defaults for a named vhost.
    """

    tempesta = {
        'config' :
        """
        srv_group vh_1_srvs {
            server ${server_ip}:8000;
        }

        # Update defaults two times, only the last one must be applied.
        sticky {
            cookie name=c_vh2 enforce;
        }
        sticky {
            cookie enforce max_misses=5 timeout=2;
        }

        vhost vh_1 {
            proxy_pass vh_1_srvs;
        }

        http_chain {
            -> vh_1;
        }
        """
    }
