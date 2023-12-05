"""
Tests for JavaScript challenge.
"""

import re
import time

from framework import tester
from framework.parameterize import param, parameterize, parameterize_class
from framework.templates import fill_template, populate_properties
from helpers import remote, tf_cfg


__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2020-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

MAX_MISSES = 2
DELAY_MIN = 1000
DELAY_RANGE = 1500


DEPROXY_CLIENT = {
    "id": "client-1",
    "type": "deproxy",
    "addr": "${tempesta_ip}",
    "port": "80",
}

DEPROXY_CLIENT_H2 = {
    "id": "client-1",
    "type": "deproxy_h2",
    "addr": "${tempesta_ip}",
    "port": "443",
    "ssl": True,
}


class BaseJSChallenge(tester.TempestaTest):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        srcdir = tf_cfg.cfg.get("Tempesta", "srcdir")
        workdir = tf_cfg.cfg.get("Tempesta", "workdir")
        remote.tempesta.run_cmd(f"cp {srcdir}/etc/js_challenge.js.tpl {workdir}")
        remote.tempesta.run_cmd(f"cp {srcdir}/etc/js_challenge.tpl {workdir}/js1.tpl")

    @staticmethod
    def client_send_pipelined_requests(client, reqs) -> list:
        client.make_requests(reqs, pipelined=True)
        client.wait_for_response(strict=True)

        return client.responses[-len(reqs) :]

    @staticmethod
    def prepare_first_req(client, host=tf_cfg.cfg.get("Tempesta", "hostname")):
        return client.create_request(
            method="GET",
            headers=[("accept", "text/html")],
            authority=host,
        )

    @staticmethod
    def prepare_second_req(
        client, cookie: tuple, uri="/", host=tf_cfg.cfg.get("Tempesta", "hostname")
    ):
        return client.create_request(
            method="GET",
            uri=uri,
            headers=[("accept", "text/html"), ("cookie", f"{cookie[0]}={cookie[1]}")],
            authority=host,
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
            "var delay_min = %d;" % DELAY_MIN,
            "var delay_range = %d;" % DELAY_RANGE,
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

    def _set_tempesta_config_without_js(self):
        """Recreate config without js_challenge directive."""
        desc = self.tempesta.copy()
        populate_properties(desc)
        new_cfg = fill_template(desc["config"], desc)
        new_cfg = re.sub(r"js_challenge[\s\w\d_/=\.\n]+;", "", new_cfg, re.M)

        self.get_tempesta().config.set_defconfig(new_cfg)

    def _set_tempesta_js_config(self):
        """Recreate config with js_challenge directive."""
        desc = self.tempesta.copy()
        populate_properties(desc)
        self.get_tempesta().config.set_defconfig(fill_template(desc["config"], desc))


@parameterize_class(
    [
        {"name": "Http", "clients": [DEPROXY_CLIENT]},
        {"name": "H2", "clients": [DEPROXY_CLIENT_H2]},
    ]
)
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
        "config": f"""
        server ${{server_ip}}:8000;
        
        listen 80;
        listen 443 proto=h2;
        
        tls_certificate ${{tempesta_workdir}}/tempesta.crt;
        tls_certificate_key ${{tempesta_workdir}}/tempesta.key;
        tls_match_any_server_name;
        
        block_action attack reply;
        block_action error reply;
        
        sticky {{
            cookie enforce name=cname max_misses={MAX_MISSES};
            js_challenge resp_code=503 delay_min={DELAY_MIN} delay_range={DELAY_RANGE} 
                        ${{tempesta_workdir}}/js1.html;
        }}
        """
    }

    def _java_script_sleep(self, cookie: str) -> None:
        """This repeats sleep from JavaScript in response body"""
        time.sleep((DELAY_MIN + int(cookie[:16], 16) % DELAY_RANGE) / 1000)

    @parameterize.expand(
        [
            param(name="GET_and_accept_html", method="GET", accept="text/html", status="503"),
            param(name="GET_and_accept_all", method="GET", accept="*/*", status="400"),
            param(name="GET_and_accept_image", method="GET", accept="image/*", status="400"),
            param(name="GET_and_accept_plain", method="GET", accept="text/plain", status="400"),
            param(name="POST", accept="text/html", method="POST", status="400"),
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

        cookie = (resp.headers.get("Set-Cookie", None),)

        if status == "503":
            self.assertIsNotNone(
                cookie, "Tempesta did not added a Set-Cookie header for a JS challenge."
            )
            self.check_resp_body_and_cookie(resp)
        else:
            self.assertIsNone(
                cookie, "Tempesta added a Set-Cookie header in a 4xx response for JS challenge."
            )
            self.assertEqual(
                resp.body,
                "",
                f"Tempesta send a response body for a reqeust with {method} method and "
                f"accept header - {accept}",
            )
        self.assertFalse(client.conn_is_closed)

    @parameterize.expand(
        [
            param(name="GET_and_accept_all", method="GET", accept="*/*"),
            param(name="POST", method="POST", accept="*/*"),
        ]
    )
    def test_second_request(self, name, method, accept):
        """Tempesta should not check a request if max_misses > 0."""
        self.start_all_services()
        client = self.get_client("client-1")
        cookie = self.process_first_js_challenge_req(client)

        self._java_script_sleep(cookie[1])

        client.send_request(
            client.create_request(
                method=method, headers=[("accept", accept), ("cookie", f"{cookie[0]}={cookie[1]}")]
            ),
            "200",
        )

    @parameterize.expand(
        [
            param(name="pass", sleep=True, second_status="200"),
            param(name="too_small", sleep=False, second_status="503"),
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
        self.assertFalse(
            client.conn_is_closed,
            "Tempesta close a connection during a JS challenge check "
            "and max_misses was not exceeded.",
        )

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
        self._set_tempesta_config_without_js()
        self.get_tempesta().reload()

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

    def test_enable_challenge_on_reload(self):
        """
        Clients sends the validating request after reload just in time and
        passes the challenge.
        """
        # Set Tempesta config with JS challenge disabled.
        self._set_tempesta_config_without_js()
        self.start_all_services()

        # Reloading Tempesta config with JS challenge.
        self._set_tempesta_js_config()
        self.get_tempesta().reload()

        client = self.get_client("client-1")
        cookie = self.process_first_js_challenge_req(client)

        self._java_script_sleep(cookie[1])

        client.send_request(self.prepare_second_req(client, cookie), "200")

    def test_not_block_after_tempesta_restart(self):
        """This case repeats the blocking of the browser on the next day."""
        self.start_all_services()
        client = self.get_client("client-1")

        # browser make request and wait for time from JS challenge
        cookie_1 = self.process_first_js_challenge_req(client)
        self._java_script_sleep(cookie_1[1])

        # browser make valid request and close session
        client.send_request(self.prepare_second_req(client, cookie_1), expected_status_code="200")
        client.stop()

        self.get_tempesta().restart()

        # browser create a new session with an existing cookie.
        # This cookie valid for browser, but invalid for Tempesta
        # because it has other timestamp after reboot
        client.start()
        client.send_request(self.prepare_second_req(client, cookie_1), expected_status_code="503")
        cookie_2 = self._check_and_get_cookie(client.last_response)

        self._java_script_sleep(cookie_2[1])
        client.send_request(self.prepare_second_req(client, cookie_2), expected_status_code="200")

    def test_new_client_session_with_exist_cookie(self):
        """Client opens an already present session: JS challenge is skipped."""
        self.start_all_services()
        client = self.get_client("client-1")

        cookie_1 = self.process_first_js_challenge_req(client)
        self._java_script_sleep(cookie_1[1])

        client.send_request(self.prepare_second_req(client, cookie_1), expected_status_code="200")
        client.restart()
        client.send_request(self.prepare_second_req(client, cookie_1), expected_status_code="200")

    @parameterize.expand(
        [
            param(name="pass", sleep=True, conn_is_closed=False),
            param(name="too_early", sleep=False, conn_is_closed=True),
        ]
    )
    def test_delay_pipelined(self, name, sleep, conn_is_closed):
        self.start_all_services()

        client = self.get_client("client-1")

        request = self.prepare_first_req(client)
        responses = self.client_send_pipelined_requests(client, [request, request, request])

        cookies = []
        for response in responses:
            self.assertEqual(
                response.status,
                "503",
                "Tempesta returned a invalid status code for the pipelined requests.",
            )
            cookies.append(self._check_and_get_cookie(response))

        if sleep:
            self._java_script_sleep(cookies[0][1])

        requests = [self.prepare_second_req(client, cookie) for cookie in cookies]
        responses = self.client_send_pipelined_requests(client, requests)

        if conn_is_closed:
            self.assertEqual(client.last_response.status, "200", "unexpected response status code")
            self.assertEqual(len(responses), 1)
        else:
            self.assertEqual(len(responses), 3)
            for resp in responses:
                self.assertEqual(resp.status, "200", "unexpected response status code")
        self.assertEqual(client.conn_is_closed, conn_is_closed)

    @parameterize.expand(
        [
            param(name="403", resp_code="resp_code=403", expected_status="403"),
            param(name="default", resp_code="", expected_status="503"),
            param(name="302", resp_code="resp_code=302", expected_status="302"),
        ]
    )
    def test_resp_code(self, name, resp_code, expected_status):
        new_cfg = self.get_tempesta().config.get_config().replace("resp_code=503", resp_code)
        self.get_tempesta().config.set_defconfig(new_cfg)

        self.start_all_services()

        client = self.get_client("client-1")
        client.send_request(self.prepare_first_req(client), expected_status)
        self.check_resp_body_and_cookie(client.last_response)
