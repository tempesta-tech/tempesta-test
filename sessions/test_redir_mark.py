"""
Redirection marks tests.
"""

import re
from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

DFLT_COOKIE_NAME = '__tfw'

class RedirectMark(tester.TempestaTest):
    """
    Sticky cookies are not enabled on Tempesta, so all clients may access the
    requested resources. No cookie challenge is used to check clients behaviour.
    """

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

    tempesta = {
        'config' :
        """
        server ${server_ip}:8000;

        sticky {
            cookie enforce max_misses=5;
        }
        """
    }

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

    def client_send_first_req(self, client, uri):
        req = ("GET %s HTTP/1.1\r\n"
               "Host: localhost\r\n"
               "\r\n" % uri)
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

        uri = response.headers.get('Location', None)
        self.assertIsNotNone(uri,
                             "Location header is missing in the response")
        return (uri, cookie)

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections(1))

    def test_good_rmark_value(self):
        """Client fully process the challenge: redirect is followed correctly,
        cookie is set correctly, so the client can get the requested resources.
        """
        self.start_all()

        client = self.get_client('deproxy')
        uri = '/'
        uri, cookie = self.client_send_first_req(client, uri)

        req = ("GET %s HTTP/1.1\r\n"
               "Host: localhost\r\n"
               "Cookie: %s=%s\r\n"
               "\r\n" % (uri, cookie[0], cookie[1]))
        response = self.client_send_req(client, req)
        self.assertEqual(response.status,'200',
                         "unexpected response status code")

    def test_rmark_without_cookie(self):
        """
        Bot which can follow redirects, but cant set cookies, will be blocked
        after few attempts.
        """
        self.start_all()

        client = self.get_client('deproxy')
        uri = '/'
        uri, _ = self.client_send_first_req(client, uri)
        uri, _ = self.client_send_first_req(client, uri)
        uri, _ = self.client_send_first_req(client, uri)
        uri, _ = self.client_send_first_req(client, uri)
        uri, _ = self.client_send_first_req(client, uri)

        req = ("GET %s HTTP/1.1\r\n"
               "Host: localhost\r\n"
               "\r\n" % uri)
        self.client_expect_block(client, req)
