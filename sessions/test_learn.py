import re
from framework import tester

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

DFLT_COOKIE_NAME = '__tfw'
# By default each server has 32 connections with Tempesta, use more attempts to
# ensure that the default round robin scheduler will switch to a new server if
# session stickiness is disabled.
ATTEMPTS = 64

class LearnSessions(tester.TempestaTest):
    """
    When a learn option is enabled, then backend server sets a cookie for the
    client and Tempesta creates a session entry for that cookie. All the
    requests with that cookie will be forwarded to that server.
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
            'Set-Cookie: client-id=jdsfhrkfj53542njfnjdmdnvjs45343n4nn4b54m\r\n'
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
            'Set-Cookie: client-id=543543kjhkjdg445345579gfjdjgkdcedhfbrh12\r\n'
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
            'Set-Cookie: client-id=432435645jkfsdhfksjdhfjkd54675jncjnsddjk\r\n'
            'Content-Length: 0\r\n\r\n'
        },
    ]

    tempesta = {
        'config' :
        """
        server ${server_ip}:8000;
        server ${server_ip}:8001;
        server ${server_ip}:8002;

        sticky {
            learn name=client-id;
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
        sids = self.get_servers_id()
        for sid in sids:
            srv = self.get_server(sid)
            if not srv.wait_for_connections(timeout=tmt):
                return False
        return True

    def reconfigure_responses(self, sid_resp_sent):
        for sid in ['server-1', 'server-2', 'server-3']:
            srv = self.get_server(sid)
            if sid == sid_resp_sent:
                status = '200 OK'
            else:
                status = '503 Service Unavailable'
            srv.set_response('HTTP/1.1 %s\r\n'
                             'Server-id: %s\r\n'
                             'Content-Length: 0\r\n\r\n' % (status, sid))

    def client_send_req(self, client, req):
        curr_responses = len(client.responses)
        client.make_requests(req)
        client.wait_for_response(timeout=1)
        self.assertEqual(curr_responses + 1, len(client.responses))

        return client.responses[-1]

    def client_send_first_req(self, client):
        req = ("GET / HTTP/1.1\r\n"
               "Host: localhost\r\n"
               "\r\n")
        response = self.client_send_req(client, req)

        self.assertEqual(response.status,'200',
                         "unexpected response status code")
        c_header = response.headers.get('Set-Cookie', None)
        self.assertIsNotNone(c_header,
                             "Set-Cookie header is missing in the response")
        match = re.search(r'([^;\s]+)=([^;\s]+)', c_header)
        self.assertIsNotNone(match,
                             "Cant extract value from Set-Cookie header")
        cookie = (match.group(1), match.group(2))

        s_id = response.headers.get('Server-id', None)
        self.assertIsNotNone(s_id,
                             "Server-id header is missing in the response")

        return (s_id, cookie)

    def client_send_next_req(self, client, cookie):
        req = ("GET / HTTP/1.1\r\n"
                   "Host: localhost\r\n"
                   "Cookie: %s=%s\r\n"
                   "\r\n" % (cookie[0], cookie[1]))
        response = self.client_send_req(client, req)
        self.assertEqual(response.status,'200',
                         "unexpected response status code")
        s_id = response.headers.get('Server-id', None)
        self.assertIsNotNone(s_id,
                             "Server-id header is missing in the response")
        return s_id

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections(1))

    def test_sessions(self):
        self.start_all()
        client = self.get_client('deproxy')

        s_id, cookie = self.client_send_first_req(client)
        self.reconfigure_responses(s_id)
        # Repeat the requests with the cookie set, all the following requests
        # will be forwarded to the same server.
        for _ in range(ATTEMPTS):
            new_s_id = self.client_send_next_req(client, cookie)
            self.assertEqual(s_id, new_s_id,
                             "Learnt session was forwarded to not-pinned server")

    def test_backend_fail(self):
        """
        Backend goes offline, but client still tries to access the resource,
        TempestaFW responds with 502 status code. But when the server is back
        online, it again serves the responses.
        """
        self.start_all()
        client = self.get_client('deproxy')
        s_id, cookie = self.client_send_first_req(client)
        srv = self.get_server(s_id)
        self.assertIsNotNone(srv, "Backend server is not known")
        srv.stop()
        for _ in range(ATTEMPTS):
            req = ("GET / HTTP/1.1\r\n"
                   "Host: localhost\r\n"
                   "Cookie: %s=%s\r\n"
                   "\r\n" % (cookie[0], cookie[1]))
            resp = self.client_send_req(client, req)
            self.assertEqual(resp.status, '502',
                             "unexpected response status code")
        srv.start()
        self.assertTrue(srv.wait_for_connections(timeout=1),
                        "Can't restart backend server")
        for _ in range(ATTEMPTS):
            new_s_id = self.client_send_next_req(client, cookie)
            self.assertEqual(s_id, new_s_id,
                             "Sticky session was forwarded to not-pinned server")

