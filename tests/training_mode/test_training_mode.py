__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

import threading
import time

from framework.deproxy import deproxy_message
from framework.helpers import analyzer, networker, remote, tf_cfg
from framework.helpers.analyzer import RST, TCP
from framework.helpers.error import ProcessBadExitStatusException
from framework.test_suite import marks, tester

NGINX_CONFIG = """
pid ${pid};
worker_processes  auto;
events {
    worker_connections   1024;
    use epoll;
}
http {
    keepalive_timeout ${server_keepalive_timeout};
    keepalive_requests ${server_keepalive_requests};
    sendfile         on;
    tcp_nopush       on;
    tcp_nodelay      on;
    open_file_cache max=1000;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;
    open_file_cache_errors off;
    error_log /dev/null emerg;
    access_log off;
    server {
        listen        ${server_ip}:8000;
        location / {
            return 200;
        }
        location /nginx_status {
            stub_status on;
        }
    }
}
"""


class TestTrainingBase(tester.TempestaTest):
    backends = [
        {
            "id": "nginx",
            "type": "nginx",
            "port": "8000",
            "status_uri": "http://${server_ip}:8000/nginx_status",
            "config": NGINX_CONFIG,
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

    def test_training_state(self):
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
        time.sleep(training_period + 1)
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
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "ssl": True,
            "port": "443",
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
                extra_config="training_z_score_request_num 1000;\n",
                conn_num=40,
                block_expected=[23, 25, False],
                frang_config="http_strict_host_checking false;\n",
            ),
            marks.Param(
                name="default_ip_block",
                extra_config="training_z_score_request_num 1000;\n",
                conn_num=40,
                block_expected=[23, 25, True],
                frang_config="http_strict_host_checking false;\nip_block 0;\n",
            ),
            marks.Param(
                name="1",
                extra_config="training_z_score_connection_num 1;\ntraining_z_score_request_num 1000;\n",
                conn_num=40,
                block_expected=[16, 19, False],
                frang_config="http_strict_host_checking false;\n",
            ),
            marks.Param(
                name="1_ip_block",
                extra_config="training_z_score_connection_num 1;\ntraining_z_score_request_num 1000;\n",
                conn_num=40,
                block_expected=[16, 19, True],
                frang_config="http_strict_host_checking false;\nip_block 0;\n",
            ),
            marks.Param(
                name="5",
                extra_config="training_z_score_connection_num 5;\ntraining_z_score_request_num 1000;\n",
                conn_num=40,
                block_expected=[0, 0, False],
                frang_config="http_strict_host_checking false;\n",
            ),
        ]
    )
    def test_connection_num_exceeded_z_score(
        self, name, extra_config, conn_num, block_expected, frang_config
    ):
        self.set_frang_config(frang_config=frang_config)
        if extra_config:
            self.get_tempesta().config.defconfig = (
                self.get_tempesta().config.defconfig + extra_config
            )
        self.start_all_services(client=False)

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
                self.wait_while_busy(client)
                client.stop()
                id_ += 1
            remote.tempesta.run_cmd("sysctl -w net.tempesta.training=0")

        client = self.get_client("curl")
        client = self.setup_curl_client(client, conn_num)

        client.start()
        if not block_expected[2]:
            self.wait_while_busy(client)
        else:
            time.sleep(10)
        client.stop()

        if not block_expected[2]:
            success_cnt = client.response_msg.count("HTTP/1.1 200 OK")
            self.assertGreaterEqual(conn_num - success_cnt, block_expected[0])
            self.assertLessEqual(conn_num - success_cnt, block_expected[1])

        client = self.get_client("deproxy")
        request = client.create_request(method="GET", headers=[])
        client.start()
        client.send_request(request)

        if block_expected[2]:
            self.assertTrue(client.wait_for_connection_close())
        else:
            self.assertTrue(client.last_response.status, "200")


class TestTrainingRequests(TestTrainingBase):
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
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

    @marks.Parameterize.expand(
        [
            marks.Param(
                name="default",
                extra_config="training_z_score_connection_num 1000;\n",
                req_num=40,
                block_expected=[23, 25],
                frang_config="http_strict_host_checking false;\n",
            ),
            marks.Param(
                name="1",
                extra_config="training_z_score_request_num 1;\ntraining_z_score_connection_num 1000;\n",
                req_num=40,
                block_expected=[16, 19],
                frang_config="http_strict_host_checking false;\n",
            ),
            marks.Param(
                name="5",
                extra_config="training_z_score_request_num 5;\ntraining_z_score_connection_num 1000;\n",
                req_num=40,
                block_expected=[0, 0],
                frang_config="http_strict_host_checking false;\n",
            ),
        ]
    )
    def test_request_num_exceeded_z_score(
        self, name, extra_config, req_num, block_expected, frang_config
    ):
        self.set_frang_config(frang_config=frang_config)
        if extra_config:
            self.get_tempesta().config.defconfig = (
                self.get_tempesta().config.defconfig + extra_config
            )
        self.start_all_services()

        with networker.create_and_cleanup_interfaces(
            node=remote.client, number_of_ip=TestTrainingBase.training_clients_n
        ) as ips:
            remote.tempesta.run_cmd("sysctl -w net.tempesta.training=1")
            id_ = 0
            for ip in ips:
                client = self.get_client(f"deproxy-interface-{id_}")
                request = client.create_request(method="GET", headers=[])
                requests = [request] * (id_ + 1)
                client.make_requests(requests)
                client.wait_for_response()
                self.assertEqual(len(client.responses), id_ + 1)
                for i in range(id_ + 1):
                    self.assertTrue(client.responses[i].status, "200")
                id_ += 1
            remote.tempesta.run_cmd("sysctl -w net.tempesta.training=0")

            client = self.get_client("deproxy")
            request = client.create_request(method="GET", headers=[])
            requests = [request] * req_num
            client.make_requests(requests)
            client.wait_for_response()

            self.assertGreaterEqual(len(client.responses), block_expected[0])
            self.assertLessEqual(len(client.responses), block_expected[1])


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

    def _do_reload(self):
        while not self.stop:
            self.get_tempesta().reload()
            time.sleep(1)

    def _do_restart_training(self):
        while not self.stop:
            remote.tempesta.run_cmd("sysctl -w net.tempesta.training=1")
            time.sleep(2)
            remote.tempesta.run_cmd("sysctl -w net.tempesta.training=0")
            time.sleep(0.5)

    def test_reload_with_training_under_load(self):
        self.set_frang_config(frang_config="http_strict_host_checking false;\n")
        self.stop = False
        self.get_tempesta().config.defconfig = (
            self.get_tempesta().config.defconfig + "training_z_score_connection_num 1;\n"
        )
        self.start_all_services(client=False)
        thread = threading.Thread(target=self._do_reload)

        with networker.create_and_cleanup_interfaces(
            node=remote.client, number_of_ip=TestTrainingBase.training_clients_n
        ) as ips:
            source_ips = ""
            for ip in ips:
                source_ips += ip + " "
            cmd_args = f'-address %s:443 -host tempesta-tech.com -source_ip "%s" -threads 4 -connections 999 -streams 100'
            client = self.get_client("gflood")
            client.options = [cmd_args % (tf_cfg.cfg.get("Tempesta", "ip"), source_ips)]
            remote.tempesta.run_cmd("sysctl -w net.tempesta.training=1")
            self.assertTrainingMode(1)
            thread.start()
            client.start()
            self.wait_while_busy(client)
            client.stop()
            remote.tempesta.run_cmd("sysctl -w net.tempesta.training=0")

        self.stop = True
        thread.join()

        conn_num = 40
        client = self.get_client("curl")
        client = self.setup_curl_client(client, conn_num)

        client.start()
        self.wait_while_busy(client)
        client.stop()

        success_cnt = client.response_msg.count("HTTP/1.1 200 OK")
        self.assertEqual(conn_num - success_cnt, 0)

    def test_restart_training_under_load(self):
        self.set_frang_config(frang_config="http_strict_host_checking false;\n")
        self.stop = False
        self.get_tempesta().config.defconfig = (
            self.get_tempesta().config.defconfig + "training_z_score_connection_num 1;\n"
        )
        self.start_all_services(client=False)
        thread = threading.Thread(target=self._do_restart_training)
        with networker.create_and_cleanup_interfaces(
            node=remote.client, number_of_ip=TestTrainingBase.training_clients_n
        ) as ips:
            source_ips = ""
            for ip in ips:
                source_ips += ip + " "
            cmd_args = f'-address %s:443 -host tempesta-tech.com -source_ip "%s" -threads 4 -connections 1000 -streams 100'
            client = self.get_client("gflood")
            client.options = [cmd_args % (tf_cfg.cfg.get("Tempesta", "ip"), source_ips)]
            thread.start()
            client.start()
            self.wait_while_busy(client)
            client.stop()

        self.stop = True
        thread.join()
