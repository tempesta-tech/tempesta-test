"""
Verify tfw_logger logging
"""

import json
import re
import time

import run_config
from helpers import remote, tf_cfg
from test_suite import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestClickHouseLogsUnderLoad(tester.TempestaTest):
    clients = [
        {
            "id": "h2load",
            "type": "external",
            "binary": "h2load",
            "ssl": True,
            "cmd_args": (
                " https://${tempesta_ip}:443/"
                f" --clients {tf_cfg.cfg.get('General', 'concurrent_connections')}"
                f" --threads {tf_cfg.cfg.get('General', 'stress_threads')}"
                f" --max-concurrent-streams {tf_cfg.cfg.get('General', 'stress_requests_count')}"
                f" --duration {tf_cfg.cfg.get('General', 'duration')}"
            ),
        },
    ]
    tempesta = dict(
        config="""
            listen 443 proto=h2,https;
            server ${server_ip}:8000;

            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;

            frang_limits { http_strict_host_checking false; }

            access_log dmesg mmap logger_config=${tfw_logger_logger_config};

        """
    )
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 201 OK\r\n" "Content-Length: 8\r\n\r\n12345678",
        },
    ]

    def setUp(self):
        super().setUp()
        self.start_all_services(client=False)

    def h2load_total_requests(self, text: str) -> int:
        res = re.findall(
            r"status codes: (\d*) 2xx, (\d*) 3xx, (\d*) 4xx, (\d*) 5xx", text, re.M | re.I
        )
        return sum([int(requests) for requests in res[0]])

    def test_all_logs_under_load(self):
        client = self.get_client("h2load")
        client.start()

        half_of_duration = run_config.DURATION / 2
        time.sleep(int(half_of_duration))

        self.wait_while_busy(client)
        client.stop()

        h2_total_requests = self.h2load_total_requests(client.stdout.decode())
        self.assertTrue(h2_total_requests)

        dmesg_logs_count = self.loggers.dmesg.access_log_records_count()
        self.assertNotEqual(dmesg_logs_count, 0)

        clickhouse_collected_rows = self.loggers.clickhouse.access_log_records_count()
        self.assertEqual(clickhouse_collected_rows, dmesg_logs_count)
        self.assertEqual(h2_total_requests, dmesg_logs_count)

    def test_all_logs_with_reload(self):
        client = self.get_client("h2load")
        client.start()

        tempesta = self.get_tempesta()

        half_of_duration = run_config.DURATION / 2
        time.sleep(int(half_of_duration))
        tempesta.reload()

        self.wait_while_busy(client)
        client.stop()

        h2_total_requests = self.h2load_total_requests(client.stdout.decode())
        self.assertTrue(h2_total_requests)

        dmesg_logs_records = self.loggers.dmesg.access_log_records_count()
        self.assertNotEqual(dmesg_logs_records, 0)

        clickhouse_collected_rows = self.loggers.clickhouse.access_log_records_count()
        self.assertEqual(clickhouse_collected_rows, dmesg_logs_records)
        self.assertEqual(h2_total_requests, dmesg_logs_records)

    def test_tfw_logger_stop_cont(self):
        client = self.get_client("h2load")
        client.start()

        half_of_duration = run_config.DURATION / 2
        time.sleep(int(half_of_duration))

        self.get_tempesta().tfw_logger_signal("STOP")
        self.get_tempesta().tfw_logger_signal("CONT")

        self.wait_while_busy(client)
        client.stop()

        h2_total_requests = self.h2load_total_requests(client.stdout.decode())
        self.assertTrue(h2_total_requests)

        dmesg_logs_records = self.loggers.dmesg.access_log_records_count()
        self.assertNotEqual(dmesg_logs_records, 0)

        clickhouse_collected_rows = self.loggers.clickhouse.access_log_records_count()
        self.assertLess(clickhouse_collected_rows, dmesg_logs_records)
        self.assertGreater(clickhouse_collected_rows, 0)
        self.assertEqual(h2_total_requests, dmesg_logs_records)
