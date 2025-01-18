"""
Verify tfw_logger logging
"""

import re
import time
from datetime import datetime, timezone
from ipaddress import IPv4Address

from helpers import tf_cfg
from helpers.clickhouse import ClickHouseFinder
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

            access_log dmesg mmap mmap_host=${tfw_logger_clickhouse_host} mmap_log=${tfw_logger_daemon_log};
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

        self.clickhouse_logs: ClickHouseFinder = ClickHouseFinder(
            host=tf_cfg.cfg.get("TFW_Logger", "clickhouse_host"),
            port=int(tf_cfg.cfg.get("TFW_Logger", "clickhouse_port")),
            username=tf_cfg.cfg.get("TFW_Logger", "clickhouse_username"),
            password=tf_cfg.cfg.get("TFW_Logger", "clickhouse_password"),
            database=tf_cfg.cfg.get("TFW_Logger", "clickhouse_database"),
            daemon_log=tf_cfg.cfg.get("TFW_Logger", "daemon_log"),
        )

        if self.clickhouse_logs.log_table_exists():
            self.clickhouse_logs.delete_all()

        self.clickhouse_logs.tfw_log_file_remove(self.get_tempesta())
        self.start_all_services(client=False)

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


class TestClickhouseLogsBufferConfiguration(TestClickhouseLogsBaseTest):
    tempesta = dict(
        config="""
            listen 80;
            server ${server_ip}:8000;

            mmap_log_buffer_size 4096;
            access_log dmesg mmap mmap_host=${tfw_logger_clickhouse_host} mmap_log=${tfw_logger_daemon_log};
        """
    )

    def test_mmap_buffer(self):
        """
        Check the buffer works fine
        """
        client = self.get_client("deproxy")
        client.start()

        self.clickhouse_logs.wait_until_tfw_logger_start(tempesta_instance=self.get_tempesta())

        self.send_simple_request(client)
        self.assertTrue(self.oops.http11_requests_exists())

        for _ in range(4100):
            self.send_simple_request(client)

        self.assertEqual(self.clickhouse_logs.total_count(), 4097)


class TestClickhouseLogsOnly(TestClickhouseLogsBaseTest):
    tempesta = dict(
        config="""
            listen 80;
            server ${server_ip}:8000;

            access_log mmap mmap_host=${tfw_logger_clickhouse_host} mmap_log=${tfw_logger_daemon_log};
        """
    )

    def test_dmesg_toggled_off(self):
        """
        Toggle off the dmesg logs sending
        """
        client = self.get_client("deproxy")
        client.start()

        self.clickhouse_logs.wait_until_tfw_logger_start(tempesta_instance=self.get_tempesta())

        self.send_simple_request(client)
        self.assertFalse(self.oops.http11_requests_exists())
        self.assertEqual(self.clickhouse_logs.total_count(), 1)


class TestClickhouseTFWLoggerFile(TestClickhouseLogsBaseTest):
    tempesta = dict(
        config="""
            listen 80;
            server ${server_ip}:8000;

            access_log mmap mmap_host=${tfw_logger_clickhouse_host} mmap_log=${tfw_logger_daemon_log};
        """
    )

    def test_twf_logger_file(self):
        """
        Check the content of tfw_logger daemon access log
        """
        client = self.get_client("deproxy")
        client.start()

        self.clickhouse_logs.wait_until_tfw_logger_start(tempesta_instance=self.get_tempesta())

        self.send_simple_request(client)
        self.assertFalse(self.oops.http11_requests_exists())

        tempesta = self.get_tempesta()
        tempesta.stop()

        stdout = self.clickhouse_logs.tfw_log_file_get_data(self.get_tempesta())
        pattern = r".*Starting daemon.*Daemon started.*Stopping daemon.*Daemon stopped.*"
        self.assertIsNotNone(re.match(pattern, stdout, re.MULTILINE | re.DOTALL))


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

        self.clickhouse_logs.wait_until_tfw_logger_start(
            tempesta_instance=self.get_tempesta(), timeout=1, raise_error=False
        )

        self.send_simple_request(client)
        self.assertFalse(self.oops.http11_requests_exists())

        self.assertFalse(self.clickhouse_logs.tfw_log_file_exists(self.get_tempesta()))
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

        self.clickhouse_logs.wait_until_tfw_logger_start(
            tempesta_instance=self.get_tempesta(), timeout=1, raise_error=False
        )

        self.send_simple_request(client)
        self.assertTrue(self.oops.http11_requests_exists())

        self.assertFalse(self.clickhouse_logs.tfw_log_file_exists(self.get_tempesta()))
        self.assertEqual(self.clickhouse_logs.total_count(), 0)


class TestClickHouseLogsCorrectnessData(TestClickhouseLogsBaseTest):
    def test_clickhouse_record_data(self):
        """
        Verify the clickhouse log record data
        """
        client = self.get_client("deproxy")
        client.start()

        self.clickhouse_logs.wait_until_tfw_logger_start(tempesta_instance=self.get_tempesta())

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
        self.assertTrue(self.oops.http11_requests_exists())
        self.assertEqual(self.clickhouse_logs.total_count(), 1)

        record = self.clickhouse_logs.last_message()
        t1 = record.timestamp.replace(microsecond=0, second=0, tzinfo=timezone.utc)
        t2 = datetime.now(tz=timezone.utc).replace(microsecond=0, second=0)
        self.assertEqual(t1, t2)
        self.assertEqual(
            record.user_agent,
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0",
        )
        self.assertEqual(record.uri, "/test")
        self.assertEqual(record.address, IPv4Address(tf_cfg.cfg.get("Client", "ip")))
        self.assertEqual(record.referer, "https://somesite.com")
        self.assertEqual(record.status, 201)
        self.assertEqual(record.version, 3)
        self.assertEqual(record.method, 3)
        self.assertEqual(record.response_content_length, 8)
        self.assertEqual(record.dropped_events, 0)
        self.assertEqual(record.vhost, "default")


class TestClickHouseLogsCorrectnessDataPostRequest(TestClickhouseLogsBaseTest):
    backends = [
        {"id": "deproxy", "type": "deproxy", "port": "8000", "response": "static"},
    ]

    def setUp(self):
        super().setUp()

        deproxy_server = self.get_server("deproxy")
        deproxy_server.set_response(
            "HTTP/1.1 500 Internal Server Error\r\n" "Content-Length: 8\r\n\r\n12345678"
        )

    def test_clickhouse_record_data_with_post(self):
        """
        Verify the clickhouse log record data
        """
        client = self.get_client("deproxy")
        client.start()

        self.clickhouse_logs.wait_until_tfw_logger_start(tempesta_instance=self.get_tempesta())

        self.send_simple_request(
            client, client.create_request(uri="/", method="POST", headers=[]), expected_status="500"
        )

        record = self.clickhouse_logs.read()[0]
        self.assertEqual(record.status, 500)
        self.assertEqual(record.method, 10)
        self.assertEqual(record.response_content_length, 8)
        self.assertEqual(record.dropped_events, 0)


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

        self.clickhouse_logs.wait_until_tfw_logger_start(tempesta_instance=self.get_tempesta())

        time_before = datetime.now(tz=timezone.utc)

        self.send_simple_request(client)

        time_after = datetime.now(tz=timezone.utc)
        self.assertEqual((time_after - time_before).seconds, 2)
        self.assertTrue(self.oops.http11_requests_exists())
        self.assertEqual(self.clickhouse_logs.total_count(), 1)

        record = self.clickhouse_logs.read()[0]
        self.assertIsNone(record.timestamp.tzname())
        self.assertGreater(record.response_time, 2000)

        __time_after = time_after.replace(tzinfo=None, microsecond=0)
        __record_time = record.timestamp.replace(microsecond=0)
        self.assertEqual(__record_time, __time_after)


class TestClickHouseLogsUnderLoad(TestClickhouseLogsBaseTest):
    clients = [
        {
            "id": "h2load",
            "type": "external",
            "binary": "h2load",
            "ssl": True,
            "cmd_args": (
                " https://${tempesta_hostname}"
                f" --clients {tf_cfg.cfg.get('General', 'concurrent_connections')}"
                f" --threads {tf_cfg.cfg.get('General', 'concurrent_connections')}"
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

            access_log dmesg mmap mmap_host=${tfw_logger_clickhouse_host} mmap_log=${tfw_logger_daemon_log};
            
        """
    )

    def h2load_total_requests(self, text: str) -> int:
        res = re.findall(
            r"status codes: (\d*) 2xx, (\d*) 3xx, (\d*) 4xx, (\d*) 5xx", text, re.M | re.I
        )
        return sum([int(requests) for requests in res[0]])

    def test_all_logs_under_load(self):
        client = self.get_client("h2load")
        self.clickhouse_logs.wait_until_tfw_logger_start(tempesta_instance=self.get_tempesta())
        client.start()

        half_of_duration = int(tf_cfg.cfg.get("General", "duration")) / 2
        time.sleep(int(half_of_duration))

        self.wait_while_busy(client)
        client.stop()

        h2_total_requests = self.h2load_total_requests(client.stdout.decode())
        self.assertIsNotNone(h2_total_requests)

        self.oops.update()
        dmesg_logs_count = self.oops.http2_requests_count()
        self.assertNotEqual(dmesg_logs_count, 0)

        clickhouse_collected_rows = self.clickhouse_logs.total_count()
        self.assertEqual(clickhouse_collected_rows, dmesg_logs_count)
        self.assertEqual(h2_total_requests, dmesg_logs_count)

    def test_all_logs_with_reload(self):
        client = self.get_client("h2load")

        self.clickhouse_logs.wait_until_tfw_logger_start(tempesta_instance=self.get_tempesta())
        client.start()

        tempesta = self.get_tempesta()

        half_of_duration = int(tf_cfg.cfg.get("General", "duration")) / 2
        time.sleep(int(half_of_duration))
        tempesta.reload()

        self.wait_while_busy(client)
        client.stop()

        h2_total_requests = self.h2load_total_requests(client.stdout.decode())
        self.assertIsNotNone(h2_total_requests)

        dmesg_logs_records = self.oops.http2_requests_count()
        self.assertNotEqual(dmesg_logs_records, 0)

        clickhouse_collected_rows = self.clickhouse_logs.total_count()
        self.assertEqual(clickhouse_collected_rows, dmesg_logs_records)
        self.assertEqual(h2_total_requests, dmesg_logs_records)

    def test_tfw_logger_stop_cont(self):
        client = self.get_client("h2load")

        self.clickhouse_logs.wait_until_tfw_logger_start(tempesta_instance=self.get_tempesta())
        client.start()

        half_of_duration = int(tf_cfg.cfg.get("General", "duration")) / 2
        time.sleep(int(half_of_duration))

        self.clickhouse_logs.tfw_logger_signal(self.get_tempesta(), "STOP")
        self.clickhouse_logs.tfw_logger_signal(self.get_tempesta(), "CONT")

        self.wait_while_busy(client)
        client.stop()

        h2_total_requests = self.h2load_total_requests(client.stdout.decode())
        self.assertIsNotNone(h2_total_requests)

        dmesg_logs_records = self.oops.http2_requests_count()
        self.assertNotEqual(dmesg_logs_records, 0)

        clickhouse_collected_rows = self.clickhouse_logs.total_count()
        self.assertLess(clickhouse_collected_rows, dmesg_logs_records)
        self.assertGreater(clickhouse_collected_rows, 0)
        self.assertEqual(h2_total_requests, dmesg_logs_records)
