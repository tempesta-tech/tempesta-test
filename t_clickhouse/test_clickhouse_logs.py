"""
Verify tfw_logger logging
"""

import re
import time
import unittest
from datetime import datetime, timezone
from ipaddress import IPv4Address

from helpers import tf_cfg
from helpers.clickhouse import ClickHouseLogStorageClient
from helpers.error import ProcessBadExitStatusException
from test_suite import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestClickhouseLogsBaseTest(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 201 OK\r\n" "Content-Length: 8\r\n\r\n12345678",
        },
    ]
    tempesta = dict(
        config="""
            listen 80;
            server ${server_ip}:8000;

            access_log dmesg mmap mmap_host=localhost mmap_log=/tmp/access.log;
        """
    )
    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        }
    ]

    def setUp(self):
        super(TestClickhouseLogsBaseTest, self).setUp()

        self.clickhouse_logs = ClickHouseLogStorageClient()

        if self.clickhouse_logs.log_table_exists():
            self.clickhouse_logs.delete_all()

        self.clean_access_log_file()
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.assertTrue(self.wait_all_connections())

    def clean_access_log_file(self):
        """
        Remove access file after previous execution
        """
        try:
            tempesta = self.get_tempesta()
            res = tempesta.node.run_cmd("rm /tmp/access.log")
            assert res == (b"", b"")

        except ProcessBadExitStatusException:
            ...

    @staticmethod
    def send_simple_request(deproxy_client, request=None, expected_status: str = "201") -> None:
        """
        The simple request with 200-code response
        """
        deproxy_client.send_request(
            request=request or deproxy_client.create_request(method="GET", headers=[]),
            expected_status_code=expected_status,
            timeout=10,
        )

    def dmesg_logs_exists(self) -> bool:
        """
        Check existing the log message record in dmesg with simple request
        """
        return self.oops.find("HTTP/1.1")

    def dmesg_logs_count(self):
        """
        Count all the simple requests in dmesg
        """
        self.oops.update()
        return len(self.oops.log_findall(r"HTTP/1.1"))

    @staticmethod
    def get_access_log_file_data(tempesta_instance) -> str:
        """
        Read data of tfw_logger daemon file
        """
        stdout, _ = tempesta_instance.node.run_cmd("cat /tmp/access.log")
        return stdout.decode()


@unittest.skip("error in the config while setting mmap_log_buffer_size")
class TestClickhouseLogsBufferConfiguration(TestClickhouseLogsBaseTest):
    tempesta = dict(
        config="""
            listen 80;
            server ${server_ip}:8000;

            mmap_log_buffer_size 4096;
            access_log dmesg mmap mmap_host=localhost mmap_log=/tmp/access.log;
        """
    )

    def test_mmap_buffer(self):
        """
        Check the buffer works fine
        """
        client = self.get_client("deproxy")
        client.start()
        time.sleep(1)

        self.send_simple_request(client)
        self.assertTrue(self.dmesg_logs_exists())

        stdout = self.get_access_log_file_data(self.get_tempesta())
        self.assertTrue(stdout.endswith("Daemon started\n"))
        self.assertEqual(self.clickhouse_logs.total_count(), 1)

        for _ in range(4100):
            self.send_simple_request(client)

        self.assertEqual(self.clickhouse_logs.total_count(), 4097)


class TestClickhouseLogsOnly(TestClickhouseLogsBaseTest):
    tempesta = dict(
        config="""
            listen 80;
            server ${server_ip}:8000;

            access_log mmap mmap_host=localhost mmap_log=/tmp/access.log;
        """
    )

    def test_dmesg_toggled_off(self):
        """
        Toggle off the dmesg logs sending
        """
        client = self.get_client("deproxy")
        client.start()

        time.sleep(1)
        self.send_simple_request(client)
        self.assertFalse(self.dmesg_logs_exists())

        stdout = self.get_access_log_file_data(self.get_tempesta())
        self.assertTrue(stdout.endswith("Daemon started\n"))
        self.assertEqual(self.clickhouse_logs.total_count(), 1)


class TestClickhouseTFWLoggerFile(TestClickhouseLogsBaseTest):
    tempesta = dict(
        config="""
            listen 80;
            server ${server_ip}:8000;

            access_log mmap mmap_host=localhost mmap_log=/tmp/access.log;
        """
    )

    def test_twf_logger_file(self):
        """
        Check the content of tfw_logger daemon access log
        """
        client = self.get_client("deproxy")
        client.start()

        time.sleep(1)

        self.send_simple_request(client)
        self.assertFalse(self.dmesg_logs_exists())

        tempesta = self.get_tempesta()
        tempesta.stop()

        stdout = self.get_access_log_file_data(self.get_tempesta())
        pattern = r".*Starting daemon.*Daemon started.*Stopping daemon.*Daemon stopped.*"
        self.assertTrue(re.match(pattern, stdout, re.MULTILINE | re.DOTALL) is not None)


class TestNoLogs(TestClickhouseLogsBaseTest):
    tempesta = dict(
        config="""
            listen 80;
            server ${server_ip}:8000;
        """
    )

    def test_dmesg_clickhouse_toggled_off(self):
        """
        Turn off all the logs
        """
        client = self.get_client("deproxy")
        client.start()

        time.sleep(1)
        self.send_simple_request(client)
        self.assertFalse(self.dmesg_logs_exists())

        tempesta = self.get_tempesta()
        stdout, _ = tempesta.node.run_cmd("ls -la /tmp | grep access.log | wc -l")
        self.assertTrue(stdout.endswith(b"0\n"))
        self.assertEqual(self.clickhouse_logs.total_count(), 0)


class TestDmesgLogsOnly(TestClickhouseLogsBaseTest):
    tempesta = dict(
        config="""
            listen 80;
            server ${server_ip}:8000;

            access_log dmesg;
        """
    )

    def test_clickhouse_toggled_off(self):
        """
        Turn on the only dmesg logging
        """
        client = self.get_client("deproxy")
        client.start()

        time.sleep(1)
        self.send_simple_request(client)
        self.assertTrue(self.dmesg_logs_exists())

        tempesta = self.get_tempesta()
        stdout, _ = tempesta.node.run_cmd("ls -la /tmp | grep access.log | wc -l")
        self.assertTrue(stdout.endswith(b"0\n"))
        self.assertEqual(self.clickhouse_logs.total_count(), 0)


class TestClickHouseLogsCorrectnessData(TestClickhouseLogsBaseTest):
    def test_clickhouse_record_data(self):
        """
        Verify the clickhouse log record data
        """
        client = self.get_client("deproxy")
        client.start()

        time.sleep(1)
        self.send_simple_request(
            client,
            client.create_request(
                uri="/test",
                method="GET",
                headers=[
                    (
                        "User-Agent",
                        "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0",
                    ),
                    ("Referer", "https://somesite.com"),
                ],
            ),
        )
        self.assertTrue(self.dmesg_logs_exists())

        stdout = self.get_access_log_file_data(self.get_tempesta())
        self.assertTrue(stdout.endswith("Daemon started\n"))
        self.assertEqual(self.clickhouse_logs.total_count(), 1)

        record = self.clickhouse_logs.read()[0]
        t1 = record.timestamp.replace(microsecond=0, second=0, tzinfo=timezone.utc)
        t2 = datetime.now(tz=timezone.utc).replace(microsecond=0, second=0)
        self.assertEqual(t1, t2)
        self.assertEqual(
            record.user_agent,
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0",
        )
        self.assertEqual(record.uri, "/test")
        self.assertEqual(record.address, IPv4Address(tf_cfg.cfg.get("Client", "address")))
        self.assertEqual(record.referer, "https://somesite.com")
        self.assertEqual(record.status, 201)
        self.assertEqual(record.version, 3)
        self.assertEqual(record.method, 3)
        self.assertEqual(record.response_content_length, 8)
        self.assertEqual(record.dropped_events, 0)
        self.assertEqual(record.vhost, "default")


class TestClickHouseLogsCorrectnessDataPostRequest(TestClickhouseLogsBaseTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 500 Internal Server Error\r\n"
            "Content-Length: 8\r\n\r\n12345678",
        },
    ]

    def test_clickhouse_record_data_with_post(self):
        """
        Verify the clickhouse log record data
        """
        client = self.get_client("deproxy")
        client.start()

        time.sleep(1)
        self.send_simple_request(
            client, client.create_request(uri="/", method="POST", headers=[]), expected_status="500"
        )

        record = self.clickhouse_logs.read()[0]
        self.assertEqual(record.status, 500)
        self.assertEqual(record.method, 10)
        self.assertEqual(record.response_content_length, 8)
        self.assertEqual(record.dropped_events, 0)


@unittest.skip("utc not default time zone")
class TestClickHouseLogsDelay(TestClickhouseLogsBaseTest):
    def test_correctness_time_of_logs_after_server_delay(self):
        """
        Verify the correctness of the clickhouse record
        timestamp value and timezone, response time
        """
        server = self.get_server("deproxy")
        server.sleep_when_receiving_data = 2

        client = self.get_client("deproxy")
        client.start()

        time.sleep(1)
        time_before = datetime.now(tz=timezone.utc)

        self.send_simple_request(client)

        time_after = datetime.now(tz=timezone.utc)
        self.assertEqual((time_before - time_after).seconds, 2)
        self.assertTrue(self.dmesg_logs_exists())
        self.assertEqual(self.clickhouse_logs.total_count(), 1)

        record = self.clickhouse_logs.read()[0]
        self.assertEqual((time_after - record.timestamp).seconds, 0)
        self.assertIsNone(record.timestamp.tzname())

        record.timestamp = record.timestamp.replace(microsecond=0).astimezone(tz=timezone.utc)
        time_after = time_after.replace(microsecond=0, tzinfo=timezone.utc)
        self.assertEqual(record.timestamp, time_after)
        self.assertEqual(record.response_time, 2000)


@unittest.skip("dmesg > total wrk, clickhouse <> dmesg")
class TestClickHouseLogsUnderLoad(TestClickhouseLogsBaseTest):
    clients = [
        {
            "id": "wrk",
            "type": "wrk",
            "addr": "${tempesta_ip}:80",
        },
    ]
    tempesta = dict(
        config="""
            listen 80;
            server ${server_ip}:8000;

            access_log dmesg mmap mmap_host=localhost mmap_log=/tmp/access.log;
        """
    )

    def prepare_client(self):
        client = self.get_client("wrk")
        client.connections = 10
        client.requests = 1000
        client.duration = 10

        return client

    def test_all_logs_under_load(self):
        client = self.prepare_client()

        time.sleep(1)
        client.start()

        time.sleep(5)

        self.wait_while_busy(client)
        client.stop()

        wrk_results = client.results()
        wrk_total_requests = wrk_results[0]
        wrk_200_ok_total = wrk_results[3][201]

        self.assertEqual(wrk_200_ok_total, wrk_total_requests)
        self.oops.update()

        dmesg_logs_count = self.dmesg_logs_count()
        self.assertNotEqual(dmesg_logs_count, 0)

        clickhouse_collected_rows = self.clickhouse_logs.total_count()
        self.assertEqual(clickhouse_collected_rows, dmesg_logs_count)
        self.assertEqual(wrk_total_requests, dmesg_logs_count)

    def test_all_logs_with_reload(self):
        client = self.prepare_client()

        time.sleep(1)
        client.start()

        tempesta = self.get_tempesta()

        time.sleep(5)
        tempesta.reload()

        self.wait_while_busy(client)
        client.stop()

        wrk_results = client.results()
        wrk_total_requests = wrk_results[0]
        wrk_200_ok_total = wrk_results[3][201]
        self.assertLess(wrk_200_ok_total, wrk_total_requests)

        dmesg_logs_records = self.dmesg_logs_count()
        self.assertNotEqual(dmesg_logs_records, 0)

        clickhouse_collected_rows = self.clickhouse_logs.total_count()
        self.assertEqual(clickhouse_collected_rows, dmesg_logs_records)
        self.assertEqual(wrk_total_requests, dmesg_logs_records)

    def test_tfw_logger_stop_cont(self):
        client = self.prepare_client()

        time.sleep(1)
        client.start()
        tempesta = self.get_tempesta()

        time.sleep(5)

        tempesta.node.run_cmd("kill -STOP $(pidof tfw_logger)")
        tempesta.node.run_cmd("kill -CONT $(pidof tfw_logger)")

        self.wait_while_busy(client)
        client.stop()

        wrk_results = client.results()
        wrk_total_requests = wrk_results[0]
        wrk_200_ok_total = wrk_results[3][201]
        self.assertEqual(wrk_200_ok_total, wrk_total_requests)

        dmesg_logs_records = self.dmesg_logs_count()
        self.assertNotEqual(dmesg_logs_records, 0)

        clickhouse_collected_rows = self.clickhouse_logs.total_count()
        self.assertLess(clickhouse_collected_rows, dmesg_logs_records)
        self.assertGreater(clickhouse_collected_rows, 0)
        self.assertEqual(wrk_total_requests, dmesg_logs_records)
