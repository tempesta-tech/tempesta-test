__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

import asyncio

from hyperframe.frame import PingFrame

from framework.deproxy import deproxy_message
from framework.helpers import analyzer, networker, remote, tf_cfg
from framework.helpers.analyzer import RST, TCP
from framework.helpers.error import ProcessBadExitStatusException
from framework.test_suite import marks, tester


class TestTrainingBase(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": ("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
        },
    ]

    tempesta = {
        "config": """
listen 443 proto=https,h2;

access_log off;

frang_limits {
    %(frang_config)s
}

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;

server ${server_ip}:8000;
""",
    }

    training_clients_n = 20

    def set_frang_config(self, frang_config: str):
        self.get_tempesta().config.defconfig = self.get_tempesta().config.defconfig % {
            "frang_config": frang_config,
        }

    def assertTrainingMode(self, expected):
        training_mode = int(remote.client.run_cmd("sysctl --values net.tempesta.training")[0])
        self.assertEqual(training_mode, expected)

    def setup_curl_client(self, client, conn_num):
        cmd_args = f"-Ikf --parallel --parallel-max %d --http1.1 --no-keepalive "
        delta = ord("z") - ord("a")
        for i in range(conn_num):
            uri = chr(ord("a") + (i % delta)) + chr(ord("a") + (i // delta))
            cmd_args += f"https://%s:443/%s " % (
                tf_cfg.cfg.get("Tempesta", "ip"),
                uri,
            )
        client.options = [cmd_args % conn_num]
        return client

    def setup_config(self, extra_config):
        self.set_frang_config(frang_config="http_strict_host_checking false;\n")
        if extra_config:
            self.get_tempesta().config.defconfig = (
                self.get_tempesta().config.defconfig + extra_config
            )

    async def setup_test(self, extra_config, start_client):
        self.setup_config(extra_config)
        await self.start_all_services(client=start_client)


class TestConfig(TestTrainingBase):
    @marks.Parameterize.expand(
        [
            marks.Param(name="negative_period", invalid_config="training_period -1;\n"),
            marks.Param(name="negative_mem", invalid_config="training_z_score_mem -1;\n"),
            marks.Param(name="negative_cpu", invalid_config="training_z_score_cpu -1;\n"),
            marks.Param(
                name="negative_req_num", invalid_config="training_z_score_request_num -1;\n"
            ),
            marks.Param(
                name="negative_conn_num", invalid_config="training_z_score_connection_num -1;\n"
            ),
        ]
    )
    def test_invalid_config(self, name, invalid_config):
        self.set_frang_config(frang_config="http_strict_host_checking false;\n")
        self.get_tempesta().config.defconfig = self.get_tempesta().config.defconfig + invalid_config
        with self.assertRaises(
            expected_exception=ProcessBadExitStatusException,
            msg="TempestaFW starts with wrong config",
        ):
            self.oops_ignore = ["ERROR"]
            self.get_tempesta().start()

    async def test_training_state(self):
        self.set_frang_config(frang_config="http_strict_host_checking false;\n")
        training_period = 2
        base_config = self.get_tempesta().config.defconfig
        self.get_tempesta().config.defconfig = (
            self.get_tempesta().config.defconfig + f"training_period {training_period};\n"
        )
        self.get_tempesta().start()
        # By default training_mode is equal to 2 (disabled)
        self.assertTrainingMode(2)
        remote.tempesta.run_cmd("sysctl -w net.tempesta.training=0")
        # Defence mode can be enabled only after training mode
        self.assertTrainingMode(2)
        remote.tempesta.run_cmd("sysctl -w net.tempesta.training=1")
        self.assertTrainingMode(1)
        await asyncio.sleep(training_period + 1)
        # Defence mode after exceeding training period
        self.assertTrainingMode(0)
        remote.tempesta.run_cmd("sysctl -w net.tempesta.training=1")
        self.assertTrainingMode(1)
        remote.tempesta.run_cmd("sysctl -w net.tempesta.training=0")
        # Set defence mode manually
        self.assertTrainingMode(0)
        training_period = 10
        self.get_tempesta().config.defconfig = base_config + f"training_period {training_period};\n"
        self.get_tempesta().reload()
        # Training mode doesn't change after Tempesta reload
        self.assertTrainingMode(0)
        remote.tempesta.run_cmd("sysctl -w net.tempesta.training=1")
        self.get_tempesta().reload()
        self.assertTrainingMode(1)


class TestTrainingConnections(TestTrainingBase):
    clients = [
        {
            "id": "curl",
            "type": "external",
            "binary": "curl",
            "ssl": True,
            "cmd_args": "",
        },
    ] + [
        {
            "id": f"curl-{id_}",
            "type": "external",
            "binary": "curl",
            "ssl": True,
            "cmd_args": "",
        }
        for id_ in range(TestTrainingBase.training_clients_n)
    ]

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="default",
                extra_config="""
                    training_z_score_request_num 1000;
                    training_z_score_cpu 1000;
                """,
                conn_num=40,
                block_expected=[23, 25],
            ),
            marks.Param(
                name="1",
                extra_config="""
                    training_z_score_connection_num 1;
                    training_z_score_request_num 1000;
                    training_z_score_cpu 1000;
                """,
                conn_num=40,
                block_expected=[16, 19],
            ),
            marks.Param(
                name="5",
                extra_config="""
                    training_z_score_connection_num 5;
                    training_z_score_request_num 1000;
                    training_z_score_cpu 1000;
                """,
                conn_num=40,
                block_expected=None,
            ),
        ]
    )
    async def test_connection_num_exceeded_z_score(
        self, name, extra_config, conn_num, block_expected
    ):
        await self.setup_test(extra_config, False)
        with networker.create_and_cleanup_interfaces(
            node=remote.client, number_of_ip=TestTrainingBase.training_clients_n
        ) as ips:
            remote.tempesta.run_cmd("sysctl -w net.tempesta.training=1")
            id_ = 0
            for ip in ips:
                client = self.get_client(f"curl-{id_}")
                cmd_args = (
                    f"-Ikf --parallel --parallel-max %d --http1.1 --no-keepalive --interface %s "
                )
                for i in range(id_ + 1):
                    cmd_args += f"https://%s:443/%s " % (
                        tf_cfg.cfg.get("Tempesta", "ip"),
                        chr(ord("a") + i),
                    )
                client.options = [cmd_args % (id_ + 1, ip)]
                client.start()
                await self.wait_while_busy(client)
                client.stop()
                id_ += 1
            remote.tempesta.run_cmd("sysctl -w net.tempesta.training=0")

        client = self.get_client("curl")
        client = self.setup_curl_client(client, conn_num)

        client.start()
        await self.wait_while_busy(client)
        client.stop()

        success_cnt = client.response_msg.count("HTTP/1.1 200 OK")
        if block_expected:
            self.assertGreaterEqual(conn_num - success_cnt, block_expected[0])
            self.assertLessEqual(conn_num - success_cnt, block_expected[1])
        else:
            self.assertEqual(conn_num, success_cnt)


class TestTrainingBaseDeproxy(TestTrainingBase):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy_h2",
            "addr": "${tempesta_ip}",
            "ssl": True,
            "port": "443",
        }
    ] + [
        {
            "id": f"deproxy-interface-{id_}",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "ssl": True,
            "port": "443",
            "interface": True,
        }
        for id_ in range(TestTrainingBase.training_clients_n)
    ]


class TestTrainingRequests(TestTrainingBaseDeproxy):
    @marks.Parameterize.expand(
        [
            marks.Param(
                name="default",
                extra_config="""
                    nonidempotent POST * *;
                    training_z_score_connection_num 1000;
                    training_z_score_cpu 1000;
                    max_concurrent_streams 10000;
                """,
                req_num=40,
                block_expected=[23, 25],
                frang_config="http_strict_host_checking false;\n",
            ),
            marks.Param(
                name="1",
                extra_config="""
                    nonidempotent POST * *;
                    training_z_score_request_num 1;
                    training_z_score_connection_num 1000;
                    training_z_score_cpu 1000;
                    max_concurrent_streams 10000;
                """,
                req_num=40,
                block_expected=[16, 19],
                frang_config="http_strict_host_checking false;\n",
            ),
            marks.Param(
                name="5",
                extra_config="""
                    nonidempotent POST * *;
                    training_z_score_request_num 5;
                    training_z_score_connection_num 1000;
                    training_z_score_cpu 1000;
                    max_concurrent_streams 10000;
                """,
                req_num=40,
                block_expected=None,
                frang_config="http_strict_host_checking false;\n",
            ),
        ]
    )
    async def test_request_num_exceeded_z_score(
        self, name, extra_config, req_num, block_expected, frang_config
    ):
        await self.setup_test(extra_config, True)
        server = self.get_server("deproxy")

        with networker.create_and_cleanup_interfaces(
            node=remote.client, number_of_ip=TestTrainingBase.training_clients_n
        ) as ips:
            remote.tempesta.run_cmd("sysctl -w net.tempesta.training=1")
            id_ = 0
            for ip in ips:
                client = self.get_client(f"deproxy-interface-{id_}")
                request = client.create_request(method="POST", headers=[])
                requests = [request] * (id_ + 1)
                server.pipelined = (id_ + 1) + 1
                server.restart()
                self.assertTrue(await server.wait_for_connections())
                client.make_requests(requests)
                self.assertTrue(await server.wait_for_requests(id_ + 1))
                self.assertEqual(len(client.responses), 0)
                server.flush()
                await client.wait_for_response()
                self.assertEqual(len(client.responses), id_ + 1)
                for i in range(id_ + 1):
                    self.assertTrue(client.responses[i].status, "200")
                id_ += 1
            remote.tempesta.run_cmd("sysctl -w net.tempesta.training=0")

            server.pipelined = req_num
            server.restart()
            self.assertTrue(await server.wait_for_connections())
            client = self.get_client("deproxy")
            request = client.create_request(method="POST", headers=[])
            requests = [request] * req_num
            client.make_requests(requests)
            if block_expected:
                self.assertTrue(await client.wait_for_connection_close())
                self.assertGreaterEqual(len(server.requests), req_num - block_expected[1])
                self.assertLessEqual(len(server.requests), req_num - block_expected[0])
            else:
                self.assertFalse(await client.wait_for_connection_close())
                await server.wait_for_requests(req_num, timeout=10)


class CommonTestCases(TestTrainingBaseDeproxy):
    clients = TestTrainingBaseDeproxy.clients + [
        {
            "id": "ctrl_frames_flood",
            "type": "external",
            "binary": "ctrl_frames_flood",
            "ssl": True,
            "cmd_args": "",
        },
    ]

    def __reset_conn_n(self, client):
        return sum(1 for line in client.stderr.decode().splitlines() if "reset by peer" in line)

    def __setup_external_client(self, cmd_args):
        client = self.get_client("ctrl_frames_flood")
        client.options = [cmd_args % tf_cfg.cfg.get("Tempesta", "ip")]
        return client

    async def __training(self):
        with networker.create_and_cleanup_interfaces(
            node=remote.client, number_of_ip=TestTrainingBase.training_clients_n
        ) as ips:
            remote.tempesta.run_cmd("sysctl -w net.tempesta.training=1")
            id_ = 0
            for ip in ips:
                client = self.get_client(f"deproxy-interface-{id_}")
                client.start()
                request = client.create_request(method="POST", headers=[], body="a" * 1000)
                requests = [request] * (id_ + 1) * 10
                client.make_requests(requests)
                await client.wait_for_response()
                self.assertEqual(len(client.responses), (id_ + 1) * 10)
                for i in range(id_ + 1):
                    self.assertTrue(client.responses[i].status, "200")
                id_ += 1
            remote.tempesta.run_cmd("sysctl -w net.tempesta.training=0")

    async def test_data_dribble(self):
        await self.setup_test("training_z_score_cpu 3;", False)
        await self.__training()
        client = self.get_client("deproxy")
        client.start()
        request = client.create_request(method="POST", headers=[], body="a" * 100000)
        await client.send_request(request, "200")
        client.segment_size = 1
        client.make_request(request)
        self.assertTrue(await client.wait_for_connection_close())

    async def test_ping_flood(self):
        defconfig = self.get_tempesta().config.defconfig

        await self.setup_test(
            """
            ctrl_frame_rate_multiplier 10000;
            training_z_score_cpu 1000;
            training_z_score_connection_num 10000;
            training_z_score_request_num 10000;
        """,
            False,
        )
        await self.__training()

        client = self.__setup_external_client(
            f"-address %s:443 -threads 1 -connections 4 -ctrl_frame_type ping_frame -frame_count 1000"
        )
        client.start()
        await self.wait_while_busy(client)
        client.stop()

        tempesta = self.get_tempesta()
        tempesta.get_stats()
        self.assertEqual(tempesta.stats.cl_ping_frame_exceeded, 0)
        self.assertEqual(tempesta.stats.wq_full, 0)
        self.assertEqual(self.__reset_conn_n(client), 0)

        self.get_tempesta().config.defconfig = defconfig
        self.setup_config(
            """
            ctrl_frame_rate_multiplier 10000;
            training_z_score_cpu 2;
            training_z_score_connection_num 1000;
            training_z_score_request_num 1000;
        """
        )
        self.get_tempesta().reload()
        remote.tempesta.run_cmd("sysctl -w net.tempesta.training=0")

        client.start()
        await self.wait_while_busy(client)
        client.stop()
        tempesta = self.get_tempesta()
        tempesta.get_stats()
        self.assertEqual(tempesta.stats.cl_ping_frame_exceeded, 0)
        self.assertEqual(tempesta.stats.wq_full, 0)
        self.assertGreater(self.__reset_conn_n(client), 0)


class TestTrainingStress(TestTrainingBase):
    clients = [
        {
            "id": f"curl",
            "type": "external",
            "binary": "curl",
            "ssl": True,
            "cmd_args": "",
        },
        {
            "id": "gflood",
            "type": "external",
            "binary": "gflood",
            "ssl": True,
            "cmd_args": "",
        },
    ]

    stop = False

    async def __start(self, extra_config):
        await self.setup_test(extra_config, False)
        self.stop = False

    async def _do_reload(self):
        while not self.stop:
            self.get_tempesta().reload()
            await asyncio.sleep(1)

    async def _do_restart_training(self):
        while not self.stop:
            remote.tempesta.run_cmd("sysctl -w net.tempesta.training=1")
            await asyncio.sleep(2)
            remote.tempesta.run_cmd("sysctl -w net.tempesta.training=0")
            await asyncio.sleep(0.5)

    def __setup_gflood_client(self, ips):
        source_ips = ""
        for ip in ips:
            source_ips += ip + " "
        cmd_args = f'-address %s:443 -host tempesta-tech.com -source_ip "%s" -threads 4 -connections 999 -streams 100'
        client = self.get_client("gflood")
        client.options = [cmd_args % (tf_cfg.cfg.get("Tempesta", "ip"), source_ips)]
        return client

    async def __test_reload_base(self, extra_config):
        await self.__start(extra_config)
        task = asyncio.create_task(self._do_reload())

        with networker.create_and_cleanup_interfaces(
            node=remote.client, number_of_ip=TestTrainingBase.training_clients_n
        ) as ips:
            client = self.__setup_gflood_client(ips)
            remote.tempesta.run_cmd("sysctl -w net.tempesta.training=1")
            self.assertTrainingMode(1)
            client.start()
            await self.wait_while_busy(client)
            client.stop()
            remote.tempesta.run_cmd("sysctl -w net.tempesta.training=0")

        self.stop = True
        await task

        conn_num = 40
        client = self.get_client("curl")
        client = self.setup_curl_client(client, conn_num)

        client.start()
        await self.wait_while_busy(client)
        client.stop()

    async def test_reload_with_training_under_load_cpu(self):
        await self.__test_reload_base(
            """
                training_z_score_cpu 1;
                training_z_score_connection_num 1000;
                training_z_score_request_num 1000;
            """
        )

    async def test_reload_with_training_under_load_conn_num(self):
        await self.__test_reload_base(
            """
                training_z_score_connection_num 1;
                training_z_score_cpu 1000;
            """
        )

        conn_num = 40
        client = self.get_client("curl")
        client = self.setup_curl_client(client, conn_num)

        client.start()
        await self.wait_while_busy(client)
        client.stop()

        success_cnt = client.response_msg.count("HTTP/1.1 200 OK")
        self.assertEqual(conn_num - success_cnt, 0)

    async def test_restart_training_under_load(self):
        await self.__start("training_z_score_connection_num 1;")
        task = None
        with networker.create_and_cleanup_interfaces(
            node=remote.client, number_of_ip=TestTrainingBase.training_clients_n
        ) as ips:
            client = self.__setup_gflood_client(ips)
            task = asyncio.create_task(self._do_restart_training())
            client.start()
            await self.wait_while_busy(client)
            client.stop()

        self.stop = True
        if task:
            await task
