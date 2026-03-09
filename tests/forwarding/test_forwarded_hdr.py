"""
Tests for validate Forwarded header.
"""

from framework.test_suite import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestForwardedBase(tester.TempestaTest, base=True):
    backends = [
        {
            "id": "backend1",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        }
    ]

    tempesta = {
        "config": """
        srv_group grp1 {
            server ${server_ip}:8000;
        }
        vhost app {
            proxy_pass grp1;
        }
        http_chain {
            -> app;
        }
        """
    }

    clients = [{"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "80"}]

    req_params = []

    response_status = "200"

    async def test_run(self):
        await self.start_all_services()
        client = self.get_client("deproxy")
        for param in self.req_params:
            with self.subTest(msg=f"Forwarded: {param}"):
                await client.send_request(
                    request=client.create_request(method="GET", headers=[("Forwarded", param)]),
                    expected_status_code=self.response_status,
                )
                client.restart()


class TestForwardedBaseAllowed(TestForwardedBase):
    """
    Test of allowed requests. Test fails, if status of any
    of requests not equal 200
    """

    req_params = [
        "host=example.com",
        "host=example.com:8080",
        "for=1.1.1.1",
        "for=1.1.1.1:8080",
        "by=2.2.2.2",
        "by=2.2.2.2:8080",
        "proto=http",
        "host=example.com;for=1.1.1.1",
        "host=example.com;for=1.1.1.1;by=2.2.2.2",
        "host=example.com;for=1.1.1.1;by=2.2.2.2;proto=http",
        "host=example.com;for=1.1.1.1, for=2.3.3.4",
        "for=1.1.1.1, for=2.3.3.4, for=4.5.2.1",
        'for="_gazonk"',
        'For="[2001:db8:cafe::17]:4711"',
        "for=192.0.2.60;proto=http;by=203.0.113.43",
        "for=192.0.2.43, for=198.51.100.17",
        "for=_hidden, for=_SEVKISEK",
    ]


class TestForwardedBaseDisallowed(TestForwardedBase):
    """
    Test of disallowed requests. Test fails, if status of any
    of requests not equal 400
    """

    response_status = "400"

    req_params = [
        "host=example.com:0",
        "host=example.com:65536",
        "host=example.com:8080;",
        "host=example.com:",
        "host=[1:2:3]",
        'host="[1:2:3]:"',
        'host="[1:aabb:3:kk]"',
        "host=[]",
        'host="[]"' "host=example.com; for=1.1.1.1",
        "host=example.com ;for=1.1.1.1",
        "host=example.com ; for=1.1.1.1",
        "myparam=123",
        "host=example.com;myparap=123",
        "for=1.1.1.$",
        'for=1".1.1.1"',
        "by=1.1.1.$",
        'by=1".1.1.1"',
        'proto=h"ttp"s',
        "proto=ht/tp",
        "for=;" "by=;",
        "proto=;",
        "host=;",
    ]


class TestForwardedBaseMalicious(TestForwardedBase):
    """
    Test of malicious requests. Test fails, if status of any
    of requests not equal 400.
    For each pattern stored in 'req_params' we append
    each malicious string stored in 'malicious'
    """

    response_status = "400"

    req_params = [
        "for=%s",
        "host=%s",
        "by=%s",
        "proto=%s",
        "host=%s;for=1.1.1.1;by=2.2.2.2;proto=http",
        "host=example.com;for=%s;by=2.2.2.2;proto=http",
        "host=example.com;for=1.1.1.1;by=%s;proto=http",
        "host=example.com;for=1.1.1.1;by=2.2.2.2;proto=%s",
    ]

    malicious = ["<xss>", '"><xss>', '" onlick=alert(1)', "' sqlinj"]

    async def test_malicious(self):
        await self.start_all_services()
        client = self.get_client("deproxy")
        for param in self.req_params:
            for evil_str in self.malicious:
                evil_param = param % evil_str
                with self.subTest(msg=f"Forwarded: {evil_param}"):
                    await client.send_request(
                        request=client.create_request(
                            method="GET", headers=[("Forwarded", evil_param)]
                        ),
                        expected_status_code=self.response_status,
                    )
                    client.restart()
