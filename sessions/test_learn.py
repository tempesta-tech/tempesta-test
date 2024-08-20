import re
import time

from framework import tester
from helpers import dmesg
from framework.parameterize import param, parameterize

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2019 Tempesta Technologies, Inc."
__license__ = "GPL2"

DFLT_COOKIE_NAME = "__tfw"
# By default each server has 32 connections with Tempesta, use more attempts to
# ensure that the default round robin scheduler will switch to a new server if
# session stickiness is disabled.
ATTEMPTS = 64


class LearnSessionsBase(tester.TempestaTest):
    def wait_all_connections(self, tmt=1):
        sids = self.get_servers_id()
        for sid in sids:
            srv = self.get_server(sid)
            if not srv.wait_for_connections(timeout=tmt):
                return False
        return True

    def reconfigure_responses(self, sid_resp_sent):
        for sid in ["server-1", "server-2", "server-3"]:
            srv = self.get_server(sid)
            if not srv:
                continue
            if sid == sid_resp_sent:
                status = "200 OK"
            else:
                status = "503 Service Unavailable"
            srv.set_response(
                "HTTP/1.1 %s\r\n" "Server-id: %s\r\n" "Content-Length: 0\r\n\r\n" % (status, sid)
            )

    def client_send_req(self, client, req):
        curr_responses = len(client.responses)
        client.make_request(req)
        client.wait_for_response(timeout=1)
        self.assertEqual(curr_responses + 1, len(client.responses))

        return client.responses[-1]

    def client_send_first_req(self, client):
        req = "GET / HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        response = self.client_send_req(client, req)

        self.assertEqual(response.status, "200", "unexpected response status code")
        c_header = response.headers.get("Set-Cookie", None)
        self.assertIsNotNone(c_header, "Set-Cookie header is missing in the response")
        match = re.search(r"([^;\s]+)=([^;\s]+)", c_header)
        self.assertIsNotNone(match, "Cant extract value from Set-Cookie header")
        cookie = (match.group(1), match.group(2))

        s_id = response.headers.get("Server-id", None)
        self.assertIsNotNone(s_id, "Server-id header is missing in the response")

        return (s_id, cookie)

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


class LearnSessions(LearnSessionsBase):
    """
    When a learn option is enabled, then backend server sets a cookie for the
    client and Tempesta creates a session entry for that cookie. All the
    requests with that cookie will be forwarded to that server.
    """

    backends = [
        {
            "id": "server-1",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Server-id: server-1\r\n"
            "Set-Cookie: client-id=jdsfhrkfj53542njfnjdmdnvjs45343n4nn4b54m\r\n"
            "Content-Length: 0\r\n\r\n",
        },
        {
            "id": "server-2",
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Server-id: server-2\r\n"
            "Set-Cookie: client-id=543543kjhkjdg445345579gfjdjgkdcedhfbrh12\r\n"
            "Content-Length: 0\r\n\r\n",
        },
        {
            "id": "server-3",
            "type": "deproxy",
            "port": "8002",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Server-id: server-3\r\n"
            "Set-Cookie: client-id=432435645jkfsdhfksjdhfjkd54675jncjnsddjk\r\n"
            "Content-Length: 0\r\n\r\n",
        },
    ]

    tempesta = {
        "config": """
        srv_group good {
            server ${server_ip}:8000;
            server ${server_ip}:8001;
            server ${server_ip}:8002;
        }

        vhost good {
            proxy_pass good;
            sticky {
                learn name=client-id;
            }
        }

        http_chain {
            %s
            ->good;
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

    def wait_all_connections(self, tmt=1):
        sids = self.get_servers_id()
        for sid in sids:
            srv = self.get_server(sid)
            if not srv.wait_for_connections(timeout=tmt):
                return False
        return True

    def reconfigure_responses(self, sid_resp_sent):
        for sid in ["server-1", "server-2", "server-3"]:
            srv = self.get_server(sid)
            if sid == sid_resp_sent:
                status = "200 OK"
            else:
                status = "503 Service Unavailable"
            srv.set_response(
                "HTTP/1.1 %s\r\n" "Server-id: %s\r\n" "Content-Length: 0\r\n\r\n" % (status, sid)
            )

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

    @parameterize.expand(
        [
            param(name="base", js_conf=""),
            param(name="other_host", js_conf='host == "test" -> jsch;'),
            param(name="same_host", js_conf='host == "good" -> jsch;'),
        ]
    )
    def test_sessions(self, name, js_conf):
        self.get_tempesta().config.defconfig = self.get_tempesta().config.defconfig % js_conf
        self.start_all()
        client = self.get_client("deproxy")

        s_id, cookie = self.client_send_first_req(client)
        self.reconfigure_responses(s_id)
        # Repeat the requests with the cookie set, all the following requests
        # will be forwarded to the same server.
        for _ in range(ATTEMPTS):
            new_s_id = self.client_send_next_req(client, cookie)
            self.assertEqual(s_id, new_s_id, "Learnt session was forwarded to not-pinned server")

    @parameterize.expand(
        [
            param(name="base", js_conf=""),
            param(name="other_host", js_conf='host == "test" ->jsch;'),
            param(name="same_host", js_conf='host == "good" ->jsch;'),
        ]
    )
    def test_backend_fail(self, name, js_conf):
        """
        Backend goes offline, but client still tries to access the resource,
        TempestaFW responds with 502 status code. But when the server is back
        online, it again serves the responses.
        """
        self.get_tempesta().config.defconfig = self.get_tempesta().config.defconfig % js_conf
        self.start_all()
        client = self.get_client("deproxy")
        s_id, cookie = self.client_send_first_req(client)
        srv = self.get_server(s_id)
        self.assertIsNotNone(srv, "Backend server is not known")
        srv.stop()
        # Remove after 2111 in Tempesta will be implemented
        time.sleep(1)
        for _ in range(ATTEMPTS):
            req = (
                "GET / HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "Cookie: %s=%s\r\n"
                "\r\n" % (cookie[0], cookie[1])
            )
            client.make_request(req)

        self.assertTrue(client.wait_for_response(20))

        self.assertEqual(len(client.responses), ATTEMPTS + 1)
        for resp in client.responses[1:]:
            self.assertEqual(resp.status, "502", "unexpected response status code")
        srv.start()
        self.assertTrue(srv.wait_for_connections(timeout=3), "Can't restart backend server")
        for _ in range(ATTEMPTS):
            new_s_id = self.client_send_next_req(client, cookie)
            self.assertEqual(s_id, new_s_id, "Sticky session was forwarded to not-pinned server")


class LearnSessionsMultipleSameSetCookie(LearnSessionsBase):
    """
    RFC 6265 4.1.1:
    Servers SHOULD NOT include more than one Set-Cookie header
    field in the same response with the same cookie-name
    """

    backends = [
        {
            "id": "server-1",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Server-id: server-1\r\n"
            "Set-Cookie: client-id=jdsfhrkfj53542njfnjdmdnvjs45343n4nn4b54m\r\n"
            "Set-Cookie: client-id=543543kjhkjdg445345579gfjdjgkdcedhfbrh12\r\n"
            "Set-Cookie: client-id=432435645jkfsdhfksjdhfjkd54675jncjnsddjk\r\n"
            "Content-Length: 0\r\n\r\n",
        }
    ]

    tempesta = {
        "config": """
        server ${server_ip}:8000;
        sticky {
            learn name=client-id;
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

    def setUp(self):
        super().setUp()
        self.klog = dmesg.DmesgFinder(disable_ratelimit=True)
        self.assert_msg = "Expected nums of warnings in `journalctl`: {exp}, but got {got}"
        # Cleanup part
        self.addCleanup(self.cleanup_klog)

    def cleanup_klog(self):
        if hasattr(self, "klog"):
            del self.klog

    @dmesg.unlimited_rate_on_tempesta_node
    def test(self):
        """
        Check that we stop processing Set-Cookie header if there are
        more than one Set-Cookie header field in the same response with
        the same cookie-name, but don't drop response, just write warning
        in dmesg.
        """
        self.start_all()
        client = self.get_client("deproxy")

        req = "GET / HTTP/1.1\r\n" "Host: localhost\r\n" "\r\n"
        response = self.client_send_req(client, req)
        self.assertEqual(response.status, "200", "unexpected response status code")

        self.assertTrue(
            self.klog.find(
                "Multiple sticky cookies found in response: 2", cond=dmesg.amount_equals(1)
            ),
            1,
        )


class LearnSessionsMultipleDiffSetCookie(LearnSessions):
    """
    Same as LearnSessions but multiple Set-Cookie headers
    """

    backends = [
        {
            "id": "server-1",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Server-id: server-1\r\n"
            "Set-Cookie: client-id=jdsfhrkfj53542njfnjdmdnvjs45343n4nn4b54m\r\n"
            "Set-Cookie: cookie1=server11\r\n"
            "Set-Cookie: cookie2=server12\r\n"
            "Content-Length: 0\r\n\r\n",
        },
        {
            "id": "server-2",
            "type": "deproxy",
            "port": "8001",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Server-id: server-2\r\n"
            "Set-Cookie: client-id=543543kjhkjdg445345579gfjdjgkdcedhfbrh12\r\n"
            "Set-Cookie: cookie1=server21\r\n"
            "Set-Cookie: cookie2=server22\r\n"
            "Content-Length: 0\r\n\r\n",
        },
        {
            "id": "server-3",
            "type": "deproxy",
            "port": "8002",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n"
            "Server-id: server-3\r\n"
            "Set-Cookie: client-id=432435645jkfsdhfksjdhfjkd54675jncjnsddjk\r\n"
            "Set-Cookie: cookie1=server31\r\n"
            "Set-Cookie: cookie2=server32\r\n"
            "Content-Length: 0\r\n\r\n",
        },
    ]

    tempesta = {
        "config": """
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
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        }
    ]


class LearnSessionsVhost(LearnSessions):
    """Same as LearnSessions, but 'sticky' configuration is inherited from
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
            learn name=client-id;
        }

        vhost vh_1 {
            proxy_pass vh_1_srvs;
        }

        http_chain {
            -> vh_1;
        }

        """
    }
