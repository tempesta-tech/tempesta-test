"""
Verify tfw_logger logging
"""

import json
from datetime import datetime, timezone
from ipaddress import IPv4Address

from helpers import remote, tf_cfg
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

            access_log dmesg mmap logger_config=${tfw_logger_logger_config};
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

    def setUp(self):
        super(TestClickhouseLogsBaseTest, self).setUp()
        logger_config = {
            "log_path": tf_cfg.cfg.get("TFW_Logger", "log_path"),
            "clickhouse": {
                "host": tf_cfg.cfg.get("TFW_Logger", "ip"),
                "port": tf_cfg.cfg.get("TFW_Logger", "clickhouse_port"),
                "user": tf_cfg.cfg.get("TFW_Logger", "clickhouse_username"),
                "password": tf_cfg.cfg.get("TFW_Logger", "clickhouse_password"),
            },
        }

        remote.tempesta.copy_file(
            filename=tf_cfg.cfg.get("TFW_Logger", "logger_config"),
            content=json.dumps(logger_config, ensure_ascii=False, indent=2),
        )

        self.start_all_services(client=False)


class TestClickhouseLogsBufferConfiguration(TestClickhouseLogsBaseTest):
    tempesta = dict(
        config="""
            listen 80;
            server ${server_ip}:8000;

            mmap_log_buffer_size 4096;
            access_log mmap logger_config=${tfw_logger_logger_config};
        """,
    )

    def test_mmap_buffer(self):
        """
        Check the buffer works fine with small value
        """
        client = self.get_client("deproxy")
        client.start()

        client.send_request(client.create_request(method="GET", headers=[]))

        self.assertWaitUntilEqual(self.loggers.clickhouse.access_log_records_count, 1)


class TestClickhouseLogsOnly(TestClickhouseLogsBaseTest):
    tempesta = dict(
        config="""
            listen 80;
            server ${server_ip}:8000;

            access_log mmap logger_config=${tfw_logger_logger_config};
        """
    )

    def test_dmesg_toggled_off(self):
        """
        Toggle off the dmesg logs sending
        """
        client = self.get_client("deproxy")
        client.start()

        self.send_simple_request(client)
        self.assertWaitUntilEqual(self.loggers.clickhouse.access_log_records_count, 1)
        self.assertWaitUntilEqual(self.loggers.dmesg.access_log_records_count, 0)


class TestClickhouseTFWLoggerFile(TestClickhouseLogsBaseTest):
    tempesta = dict(
        config="""
            listen 80;
            server ${server_ip}:8000;

            access_log mmap logger_config=${tfw_logger_logger_config};
        """
    )

    def test_twf_logger_file(self):
        """
        Check the content of tfw_logger daemon access log
        """
        self.assertWaitUntilTrue(lambda: self.loggers.clickhouse.find("Daemon started"))

        self.get_tempesta().stop_tempesta()
        self.assertWaitUntilTrue(lambda: self.loggers.clickhouse.find("Device closed"))


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

        self.send_simple_request(client)
        self.assertWaitUntilEqual(self.loggers.dmesg.access_log_records_count, 0)

        self.assertFalse(self.get_tempesta().tfw_log_file_exists())
        self.assertWaitUntilEqual(self.loggers.clickhouse.access_log_records_count, 0)


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

        self.send_simple_request(client)
        self.assertWaitUntilEqual(self.loggers.dmesg.access_log_records_count, 1)

        self.assertFalse(self.get_tempesta().tfw_log_file_exists())
        self.assertWaitUntilEqual(self.loggers.clickhouse.access_log_records_count, 0)


class TestClickHouseLogsCorrectnessData(TestClickhouseLogsBaseTest):
    tempesta = dict(
        config="""
            listen 443 proto=https,h2;
            server ${server_ip}:8000;
            
            tls_certificate ${tempesta_workdir}/tempesta.crt;
            tls_certificate_key ${tempesta_workdir}/tempesta.key;
            tls_match_any_server_name;
            
            access_log dmesg mmap logger_config=${tfw_logger_logger_config};
        """
    )
    clients = [
        {"id": "deproxy", "type": "deproxy", "addr": "${tempesta_ip}", "port": "443", "ssl": True}
    ]

    def test_clickhouse_record_data(self):
        """
        Verify the clickhouse log record data
        """
        client = self.get_client("deproxy")
        client.start()

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

        self.assertWaitUntilEqual(self.loggers.dmesg.access_log_records_count, 1)
        self.assertWaitUntilEqual(self.loggers.clickhouse.access_log_records_count, 1)

        record = self.loggers.clickhouse.access_log_last_message()
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
        self.assertEqual(record.ja5h, 2551211360704)
        self.assertEqual(record.ja5t, 7407189765761859584)


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

        self.send_simple_request(
            client, client.create_request(uri="/", method="POST", headers=[]), expected_status="500"
        )

        self.assertWaitUntilCountEqual(
            lambda: self.loggers.clickhouse.access_log_find(
                status=500, method="POST", content_length=8, dropped_events=0
            ),
            1,
        )


class TestClickHouseLogsDelay(TestClickhouseLogsBaseTest):
    def test_correctness_time_of_logs_after_server_delay(self):
        """
        Verify the correctness of the clickhouse record
        timestamp value and timezone, response time
        """
        server = self.get_server("deproxy")
        server.delay_before_sending_response = 2

        client = self.get_client("deproxy")
        client.start()

        time_before = datetime.now(tz=timezone.utc)

        self.send_simple_request(client)

        time_after = datetime.now(tz=timezone.utc)
        self.assertEqual((time_after - time_before).seconds, 2)
        self.assertWaitUntilEqual(self.loggers.dmesg.access_log_records_count, 1)
        self.assertWaitUntilEqual(self.loggers.clickhouse.access_log_records_count, 1)

        record = self.loggers.clickhouse.access_log_last_message()
        self.assertIsNone(record.timestamp.tzname())
        self.assertGreaterEqual(record.response_time, server.delay_before_sending_response * 1000)

        __time_after = time_after.replace(tzinfo=None, microsecond=0)
        __record_time = record.timestamp.replace(microsecond=0)
        self.assertGreaterEqual(__time_after, __record_time)


class TestClickhouseLogTiming(tester.TempestaTest):
    """
    Test that first access logs appear immediately in ClickHouse
    """

    tempesta = {
        "config": """
            listen 80;
            server ${server_ip}:8000;
            access_log mmap logger_config=/tmp/tfw_logger_test.json;
        """
    }

    clients = [
        {
            "id": "curl",
            "type": "curl",
            "addr": "${tempesta_ip}:80",
        },
        {
            "id": "parallel",
            "type": "curl",
            "addr": "${tempesta_ip}:80",
            "uri": "/[1-5]",
            "parallel": 5,
        },
    ]

    def test_immediate_log_appearance(self):
        """
        This test demonstrates the original problem
        """
        self.get_tempesta().start()

        client = self.get_client("curl")

        client.start()
        self.assertTrue(client.wait_for_finish())
        client.stop()

        self.assertWaitUntilEqual(
            func=self.loggers.clickhouse.access_log_records_count, second=1, poll_freq=0.01
        )

    def test_multiple_requests(self):
        """
        Test that multiple requests are send
        """
        self.get_tempesta().start()

        client = self.get_client("parallel")

        client.start()
        self.assertTrue(client.wait_for_finish())
        client.stop()

        self.assertWaitUntilEqual(
            func=self.loggers.clickhouse.access_log_records_count, second=5, poll_freq=0.01
        )
