import re

from framework import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2019 Tempesta Technologies, Inc."
__license__ = "GPL2"

DFLT_COOKIE_NAME = "__tfw"
# By default each server has 32 connections with Tempesta, use more attempts to
# ensure that the default round robin scheduler will switch to a new server if
# session stickiness is disabled.
ATTEMPTS = 64


class StickySessions(tester.TempestaTest):
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

        sticky {
            cookie enforce;
            sticky_sessions;
        }

        """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        }
    ]

    def client_send_req(self, client, req):
        curr_responses = len(client.responses)
        client.make_requests(req)
        client.wait_for_response(timeout=1)
        self.assertEqual(curr_responses + 1, len(client.responses))

        return client.responses[-1]

    def client_send_first_req(self, client):
        req = "GET / HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        response = self.client_send_req(client, req)

        self.assertEqual(response.status, "302", "unexpected response status code")
        c_header = response.headers.get("Set-Cookie", None)
        self.assertIsNotNone(c_header, "Set-Cookie header is missing in the response")
        match = re.search(r"([^;\s]+)=([^;\s]+)", c_header)
        self.assertIsNotNone(match, "Cant extract value from Set-Cookie header")
        cookie = (match.group(1), match.group(2))

        return cookie

    def client_send_next_req(self, client, cookie):
        req = (
            "GET / HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Cookie: %s=%s\r\n"
            "\r\n" % (cookie[0], cookie[1])
        )
        response = self.client_send_req(client, req)
        self.assertEqual(response.status, "200", "unexpected response status code")
        s_id = response.headers.get("Server-id", None)
        self.assertIsNotNone(s_id, "Server-id header is missing in the response")
        return s_id

    def start_all(self):
        self.start_all_servers()
        self.start_tempesta()
        self.start_all_clients()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections(1))

    def test_sessions(self):
        self.start_all()
        client = self.get_client("deproxy")
        # Make a first request and remember the backend id
        cookie = self.client_send_first_req(client)
        s_id = self.client_send_next_req(client, cookie)
        # Repeat the requests with the cookie set, all the following requests
        # will be forwarded to the same server.
        for _ in range(ATTEMPTS):
            new_s_id = self.client_send_next_req(client, cookie)
            self.assertEqual(s_id, new_s_id, "Sticky session was forwarded to not-pinned server")


class StickySessionsVhost(StickySessions):
    """Same as StickySessions, but 'sticky' configuration is inherited from
    updated defaults for a named vhost.
    """

    tempesta = {
        "config": """
        srv_group vh_1_srvs {
            server ${server_ip}:8000;
            server ${server_ip}:8001;
            server ${server_ip}:8002;
        }

        # Update defaults two times, only the last one must be applied.
        sticky {
            cookie name=c_vh2 enforce;
        }
        sticky {
            cookie enforce;
            sticky_sessions;
        }

        vhost vh_1 {
            proxy_pass vh_1_srvs;
        }

        http_chain {
            -> vh_1;
        }

        """
    }


class StickySessionsPersistense(StickySessions):
    """
    Test how the sticky sessions are handled when a pinned server does down.
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
        {
            "id": "server-4",
            "type": "deproxy",
            "port": "8003",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Server-id: server-4\r\n"
            "Content-Length: 0\r\n\r\n",
        },
    ]

    tempesta = {
        "config": """
        srv_group primary {
            server ${server_ip}:8000;
            server ${server_ip}:8001;
        }
        srv_group reserved {
            server ${server_ip}:8002;
            server ${server_ip}:8003;
        }

        vhost main {
            proxy_pass primary backup=reserved;

                sticky {
                    cookie enforce;
                    sticky_sessions;
            }
        }

        http_chain {
            -> main;
        }

        """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        }
    ]

    def test_sessions(self):
        """
        Backend goes offline, but client still tries to access the resource,
        TempestaFW responds with 502 status code. But when the server is back
        online, it again serves the responses.
        """
        self.start_all()
        client = self.get_client("deproxy")
        # Make a first request and remember the backend id
        cookie = self.client_send_first_req(client)
        s_id = self.client_send_next_req(client, cookie)
        # If server is down, and the allow_failover option is not present,
        # new requests in the session won't be forwarded to any other backends.
        # But when the server is back online, it will continue to serve the
        # session.
        srv = self.get_server(s_id)
        self.assertIsNotNone(srv, "Backend server is not known")
        srv.stop()
        for _ in range(ATTEMPTS):
            req = (
                "GET / HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "Cookie: %s=%s\r\n"
                "\r\n" % (cookie[0], cookie[1])
            )
            resp = self.client_send_req(client, req)
            self.assertEqual(resp.status, "502", "unexpected response status code")
        srv.start()
        self.assertTrue(srv.wait_for_connections(timeout=3), "Can't restart backend server")
        for _ in range(ATTEMPTS):
            new_s_id = self.client_send_next_req(client, cookie)
            self.assertEqual(s_id, new_s_id, "Sticky session was forwarded to not-pinned server")


class StickySessionsPersistenseVhost(StickySessionsPersistense):
    """Same as StickySessionsPersistense, but 'sticky' configuration is
    inherited from updated defaults for a named vhost.

    There is no test for implicit default vhost, since 'proxy_pass' directive
    can't be defined outside vhost. Without this directive the whole test for
    implicit default vhost has no sense.
    """

    tempesta = {
        "config": """
        srv_group primary {
            server ${server_ip}:8000;
            server ${server_ip}:8001;
        }
        srv_group reserved {
            server ${server_ip}:8002;
            server ${server_ip}:8003;
        }

        # Update defaults two times, only the last one must be applied.
        sticky {
            cookie name=c_vh2 enforce;
        }
        sticky {
            cookie enforce;
            sticky_sessions;
        }

        vhost main {
            proxy_pass primary backup=reserved;
        }

        http_chain {
            -> main;
        }

        """
    }


class StickySessionsFailover(StickySessions):
    """
    Test how the sticky sessions is moved to a new server when original one is
    down.
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
        {
            "id": "server-4",
            "type": "deproxy",
            "port": "8003",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Server-id: server-4\r\n"
            "Content-Length: 0\r\n\r\n",
        },
    ]

    tempesta = {
        "config": """
        srv_group primary {
            server ${server_ip}:8000;
            server ${server_ip}:8001;
        }
        srv_group reserved {
            server ${server_ip}:8002;
            server ${server_ip}:8003;
        }

        vhost main {
            proxy_pass primary backup=reserved;

                sticky {
                    cookie enforce;
                    sticky_sessions allow_failover;
            }
        }

        http_chain {
            -> main;
        }

        """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        }
    ]

    def test_sessions(self):
        """
        Backend goes offline, another backend from the primary group takes the
        load. When the original backend server goes back online, the session
        remains on fallbacked server.
        """
        self.start_all()
        client = self.get_client("deproxy")
        # Make a first request and remember the backend id
        cookie = self.client_send_first_req(client)
        s_id = self.client_send_next_req(client, cookie)

        srv = self.get_server(s_id)
        self.assertIsNotNone(srv, "Backend server is not known")
        srv.stop()

        failovered_s_id = self.client_send_next_req(client, cookie)
        self.assertIn(
            failovered_s_id, ["server-1", "server-2"], "session is pinned to unexpected server"
        )

        srv.start()
        self.assertTrue(srv.wait_for_connections(timeout=3), "Can't restart backend server")
        for _ in range(ATTEMPTS):
            new_s_id = self.client_send_next_req(client, cookie)
            self.assertEqual(
                failovered_s_id, new_s_id, "Sticky session was forwarded to not-pinned server"
            )

    def test_sessions_reserved_server(self):
        """
        Same as test_sessions(), but a server from a reserved server group picks
        up the load. The session remains on the backend server even if primary
        servers are back online.
        """
        self.start_all()
        client = self.get_client("deproxy")
        # Make a first request and remember the backend id
        cookie = self.client_send_first_req(client)
        self.client_send_next_req(client, cookie)

        srv1 = self.get_server("server-1")
        srv1.stop()
        srv2 = self.get_server("server-2")
        srv2.stop()

        failovered_s_id = self.client_send_next_req(client, cookie)
        self.assertIn(
            failovered_s_id, ["server-3", "server-4"], "session is pinned to unexpected server"
        )

        srv1.start()
        srv2.start()
        self.assertTrue(srv1.wait_for_connections(timeout=3), "Can't restart backend server")
        self.assertTrue(srv2.wait_for_connections(timeout=3), "Can't restart backend server")
        for _ in range(ATTEMPTS):
            new_s_id = self.client_send_next_req(client, cookie)
            self.assertEqual(
                failovered_s_id, new_s_id, "Sticky session was forwarded to not-pinned server"
            )


class StickySessionsFailoverVhost(StickySessionsFailover):
    """Same as StickySessionsFailover, but 'sticky' configuration is
    inherited from updated defaults for a named vhost.

    There is no test for implicit default vhost, since 'proxy_pass' directive
    can't be defined outside vhost. Without this directive the whole test for
    implicit default vhost has no sense.
    """

    tempesta = {
        "config": """
        srv_group primary {
            server ${server_ip}:8000;
            server ${server_ip}:8001;
        }
        srv_group reserved {
            server ${server_ip}:8002;
            server ${server_ip}:8003;
        }

        # Update defaults two times, only the last one must be applied.
        sticky {
            cookie name=c_vh2 enforce;
        }
        sticky {
            cookie enforce;
            sticky_sessions allow_failover;
        }

        vhost main {
            proxy_pass primary backup=reserved;
        }

        http_chain {
            -> main;
        }

        """
    }
