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
        """
        This test checks that Tempesta FW doesn't start with wrong `client_mem`
        option.
        """
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

    async def send_request_and_check_conn_close(self, client, request):
        client.make_request(request)
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
            "client_mem": "client_mem 5000 10000;\n",
        },
        {
            "name": "Https",
            "clients": [DEPROXY_CLIENT_SSL],
            "client_mem": "client_mem 5000 10000;\n",
        },
        {
            "name": "H2",
            "clients": [DEPROXY_CLIENT_H2],
            "client_mem": "client_mem 20000 40000;\n",
        },
    ]
)
class TestBlockByMemExceeded(TestBlockByMemExceededBase):
    async def test_request(self):
        """
        This test checks that Tempesta FW drop client connection
        if request exceeded `client_mem` limit.
        """
        self.update_tempesta_config(self.client_mem)
        await self.start_all_services()

        client = self.get_client("deproxy")
        request = client.create_request(
            method="POST", uri="/", headers=[("Content-Length", "30000")], body="a" * 30000
        )

        await self.send_request_and_check_conn_close(client, request)

    async def test_response(self):
        """
        This test checks that Tempesta FW drop client connection
        if response exceeded `client_mem` limit. Check that
        client received 403 error response before connection
        will be closed.
        """
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

        await client.send_request(request, "403")
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

    async def __do_reload_impl(self, base_config, i):
        config = base_config + "client_mem 10000 20000;\n" if i % 2 == 0 else base_config
        self.get_tempesta().config.defconfig = config
        self.get_tempesta().reload()
        await asyncio.sleep(1)

    async def __do_reload(self):
        base_config = self.get_tempesta().config.defconfig
        await self.__do_reload_impl(base_config, 0)
        await self.__do_reload_impl(base_config, 1)

    async def test_under_load(self):
        """
        This test checks that there is no crashes if we reload
        Tempesta FW with `client_mem` options under heavy load.
        (Tempesta FW deletes special data structure used for
        client memory accounting in very sofisticated way).
        """
        await self.start_all_services(client=False)
        client = self.get_client("gflood")
        self.create_task(self.__do_reload)
        client.start()
        await self.wait_while_busy(client)
        client.stop()


@marks.parameterize_class(
    [
        {
            "name": "Http",
            "clients": [DEPROXY_CLIENT],
        },
        {
            "name": "Https",
            "clients": [DEPROXY_CLIENT_SSL],
        },
        {
            "name": "H2",
            "clients": [DEPROXY_CLIENT_H2],
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
        """
        This test check that `client_mem` option is reconfigurable.
        First of all start Tempesta FW without `client_mem` option,
        send request with long body and check that we successfully
        receive response. Reload Tempesta FW with strong `client_mem`
        limit and check that we close client connection, because
        `client_mem` limit is exceeded.
        """
        await self.start_all_services()
        client = self.get_client("deproxy")
        request = client.create_request(
            method="POST", uri="/", headers=[("Content-Length", "10000")], body="a" * 10000
        )

        await client.send_request(request, "200")
        self.update_tempesta_config("client_mem 10000 20000;\n")
        self.get_tempesta().reload()
        await self.send_request_and_check_conn_close(client, request)


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

    async def test(self):
        """
        This test check that Tempesta FW drops client connection under ping
        flood, if client_mem is exceeded hard limit.
        """
        await self.start_all_services()

        ping_count = 10000

        client = self.get_client("deproxy")
        for _ in range(0, ping_count):
            client.ping()

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
        return f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\n\r\n{body}"

    async def test_all_clients_active(self):
        """
        This test checks Tempesta FW behaviour, when count of clients
        exceeded LRU size. In this case Tempesta FW remove old clients
        and delete structure, which is used for memory accounting.
        """
        await self.start_all_services()
        server = self.get_server("deproxy")

        server.set_response(self.make_resp("x" * 10000))

        i = 0
        for client in self.get_clients():
            client.start()
            request = client.create_request(method="GET", uri="/", headers=[])
            client.make_requests([request] * 10)
            await server.wait_for_requests((i + 1) * 10, strict=True)
            await client.wait_for_response()
            self.assertTrue(len(client.responses), 10)
