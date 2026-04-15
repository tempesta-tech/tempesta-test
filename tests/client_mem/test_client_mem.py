"""Tests for client mem configuration."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import asyncio
import run_config
from framework.helpers import error
from framework.test_suite import marks, tester

DEPROXY_CLIENT = {
    "id": "deproxy",
    "type": "deproxy",
    "addr": "${tempesta_ip}",
    "port": "80",
}

DEPROXY_CLIENT_SSL = {
    "id": "deproxy",
    "type": "deproxy",
    "addr": "${tempesta_ip}",
    "port": "443",
    "ssl": True,
}

DEPROXY_CLIENT_H2 = {
    "id": "deproxy",
    "type": "deproxy_h2",
    "addr": "${tempesta_ip}",
    "port": "443",
    "ssl": True,
}

DEPROXY_SERVER = {
    "id": "deproxy",
    "type": "deproxy",
    "port": "8000",
    "response": "static",
    "response_content": "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: 0\r\n\r\n",
}


class TestClientMemBase(tester.TempestaTest):
    def update_tempesta_config(self, client_mem_config: str):
        new_config = self.get_tempesta().config.defconfig
        self.get_tempesta().config.defconfig = new_config + client_mem_config


class TestClientMemConfig(TestClientMemBase):
    """
    This class contains tests for 'client_mem' directives.
    """

    tempesta = {
        "config": """
listen 80;
"""
    }

    @marks.Parameterize.expand(
        [
            marks.Param(name="not_present", client_mem_config="client_mem;\n"),
            marks.Param(name="to_many_args", client_mem_config="client_mem 1 3 5;\n"),
            marks.Param(name="no_attrs", client_mem_config="client_mem 1 b=3;\n"),
            marks.Param(name="value_1", client_mem_config="client_mem 11aa;\n"),
            marks.Param(name="soft_is_greater_then_hard", client_mem_config="client_mem 10 1;\n"),
        ]
    )
    async def test_invalid(self, name, client_mem_config):
        tempesta = self.get_tempesta()
        self.update_tempesta_config(client_mem_config)
        self.oops_ignore = ["ERROR"]
        with self.assertRaises(error.ProcessBadExitStatusException):
            tempesta.start()


class TestBlockByMemExceededBase(TestClientMemBase):
    tempesta = {
        "config": """
listen 80;
listen 443 proto=h2,https;

server ${server_ip}:8000;

block_action attack reply;
block_action error reply;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
""",
    }

    backends = [DEPROXY_SERVER]
    expect_response = None

    async def send_request_and_check_response_and_conn_close(self, client, request):
        client.make_request(request)
        if self.expect_response:
            await client.wait_for_response(strict=True)
            self.assertTrue(client.last_response.status, "403")
        """
        For http2 connection Tempesta FW adjust memory on
        frame level, so connection will be closed with
        TCP RST without any response
        """
        await client.wait_for_connection_close(strict=True)


@marks.parameterize_class(
    [
        {
            "name": "Http",
            "clients": [DEPROXY_CLIENT],
            "expect_response": True,
            "client_mem": "client_mem 10000 20000;\n",
        },
        {
            "name": "Https",
            "clients": [DEPROXY_CLIENT_SSL],
            "expect_response": True,
            "client_mem": "client_mem 10000 20000;\n",
        },
        {
            "name": "H2",
            "clients": [DEPROXY_CLIENT_H2],
            "expect_response": False,
            "client_mem": "client_mem 20000 40000;\n",
        },
    ]
)
class TestBlockByMemExceeded(TestBlockByMemExceededBase):
    async def test_request(self):
        self.update_tempesta_config(self.client_mem)
        await self.start_all_services()

        client = self.get_client("deproxy")
        request = client.create_request(
            method="POST", uri="/", headers=[("Content-Length", "10000")], body="a" * 10000
        )

        await self.send_request_and_check_response_and_conn_close(client, request)

    async def test_response(self):
        self.update_tempesta_config(self.client_mem)
        await self.start_all_services()

        srv: StaticDeproxyServer = self.get_server("deproxy")
        srv.set_response(
            "HTTP/1.1 200 OK\r\n"
            + "Content-Length: 10000\r\n"
            + "Content-Type: text/html\r\n"
            + "\r\n"
            + "a" * 10000
        )

        client = self.get_client("deproxy")
        request = client.create_request(
            method="GET",
            uri="/",
            headers=[],
        )

        client.make_request(request)
        if not run_config.TCP_SEGMENTATION:
            await client.wait_for_response(strict=True)
            self.assertTrue(client.last_response.status, "403")
        await client.wait_for_connection_close(strict=True)


class TestReconfigClientMemStress(tester.TempestaTest):
    tempesta = {
        "config": """
listen 80;
listen 443 proto=h2,https;

server ${server_ip}:8000;

block_action attack reply;
block_action error reply;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
""",
    }

    backends = [DEPROXY_SERVER]

    clients = [
        {
            "id": "gflood",
            "type": "external",
            "binary": "gflood",
            "ssl": True,
            "cmd_args": "-address ${tempesta_ip}:443 -host tempesta-tech.com -threads 4 -connections 100 -streams 100",
        },
    ]

    stop = False

    async def _do_reload(self):
        base_config = self.get_tempesta().config.defconfig
        i = 0
        while not self.stop:
            if i % 2 == 0:
                config = base_config + "client_mem 10000 20000;\n"
            else:
                config = base_config
            i = i + 1
            self.get_tempesta().config.defconfig = config
            self.get_tempesta().reload()
            await asyncio.sleep(1)

    async def test_under_load(self):
        await self.start_all_services(client=False)
        client = self.get_client("gflood")
        task = asyncio.create_task(self._do_reload())
        client.start()
        await self.wait_while_busy(client)
        client.stop()
        self.stop = True
        await task


@marks.parameterize_class(
    [
        {
            "name": "Http",
            "clients": [DEPROXY_CLIENT],
            "expect_response": True,
            "client_mem": "client_mem 10000 20000;\n",
        },
        {
            "name": "Https",
            "clients": [DEPROXY_CLIENT_SSL],
            "expect_response": True,
            "client_mem": "client_mem 10000 20000;\n",
        },
        {
            "name": "H2",
            "clients": [DEPROXY_CLIENT_H2],
            "expect_response": False,
            "client_mem": "client_mem 20000 40000;\n",
        },
    ]
)
class TestReconfigClientMem(TestBlockByMemExceededBase):
    tempesta = {
        "config": """
listen 80;
listen 443 proto=h2,https;

server ${server_ip}:8000;

block_action attack reply;
block_action error reply;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
""",
    }

    backends = [DEPROXY_SERVER]

    async def test(self):
        await self.start_all_services()
        client = self.get_client("deproxy")
        request = client.create_request(
            method="POST", uri="/", headers=[("Content-Length", "10000")], body="a" * 10000
        )

        await client.send_request(request, "200")
        self.update_tempesta_config("client_mem 10000 20000;\n")
        self.get_tempesta().reload()
        await self.send_request_and_check_response_and_conn_close(client, request)


class TestBlockByMemExceededByPing(tester.TempestaTest):
    tempesta = {
        "config": """
listen 443 proto=h2;

server ${server_ip}:8000;

client_mem 500 1000;
block_action attack reply;
block_action error reply;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
""",
    }

    clients = [DEPROXY_CLIENT_H2]

    backends = [DEPROXY_SERVER]

    def _ping(self, client):
        client.h2_connection.ping(opaque_data=b"\x00\x01\x02\x03\x04\x05\x06\x07")
        client.send_bytes(client.h2_connection.data_to_send())
        client.h2_connection.clear_outbound_data_buffer()

    async def test(self):
        await self.start_all_services()

        ping_count = 10000

        client = self.get_client("deproxy")
        for _ in range(0, ping_count):
            self._ping(client)

        await client.wait_for_connection_close(strict=True)


class TestSeveralClientsWithSmallLrusize(tester.TempestaTest):
    tempesta = {
        "config": """
listen 443 proto=h2,https;

server ${server_ip}:8000;

client_lru_size 1;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;
""",
    }

    clients = [
        {
            "id": f"deproxy-interface-{id_}",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "443",
            "interface": True,
            "ssl": True,
        }
        for id_ in range(3)
    ]

    backends = [DEPROXY_SERVER]

    @staticmethod
    def make_resp(body):
        return "HTTP/1.1 200 OK\r\n" "Content-Length: " + str(len(body)) + "\r\n\r\n" + body

    async def test_all_clients_active(self):
        await self.start_all_services()
        server = self.get_server("deproxy")

        server.set_response(self.make_resp("x" * 10000))

        for id_ in range(3):
            client = self.get_client(f"deproxy-interface-{id_}")
            client.start()

        for id_ in range(3):
            client = self.get_client(f"deproxy-interface-{id_}")
            for i in range(10):
                request = client.create_request(method="GET", uri="/", headers=[])
                client.make_request(request)
                await server.wait_for_requests(id_ * 10 + i, strict=True)
            await client.wait_for_response()
            self.assertTrue(len(client.responses), 10)
