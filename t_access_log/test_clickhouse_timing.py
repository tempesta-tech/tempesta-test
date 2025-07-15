"""
Test for verifying that first log appear in ClickHouse immediately after startup
"""

import json
import os
import subprocess
import time

import clickhouse_connect

from test_suite import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestClickhouseLogTiming(tester.TempestaTest):
    """
    Test that first access logs appear immediately in ClickHouse
    """

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        },
    ]

    tempesta = {
        "config": """
            listen 80;
            server ${server_ip}:8000;
            access_log dmesg;
            access_log mmap logger_config=/tmp/tfw_logger_test.json;
        """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        }
    ]

    def setUp(self):
        super().setUp()

        logger_config = {
            "log_path": "/tmp/tfw_logger.log",  # Use standard path expected by test framework
            "buffer_size": 16777216,
            "clickhouse": {
                "host": "localhost",
                "port": 9000,
                "user": "default",
                "password": "",
                "table_name": "access_log",
                "max_events": 1,
                "max_wait_ms": 10,
            },
        }

        # Write config file
        with open("/tmp/tfw_logger_test.json", "w") as f:
            json.dump(logger_config, f)

        # Get ClickHouse client
        self.clickhouse_client = clickhouse_connect.get_client()

        # Verify table exists
        table_exists = self.clickhouse_client.command("EXISTS TABLE access_log")
        self.assertTrue(table_exists, "access_log table should exist")

    def tearDown(self):
        super().tearDown()
        # Clean up test config file
        if os.path.exists("/tmp/tfw_logger_test.json"):
            os.remove("/tmp/tfw_logger_test.json")

    def verify_config_exists(self):
        """Verify config file exists"""
        self.assertTrue(
            os.path.exists("/tmp/tfw_logger_test.json"), "Logger config file should exist"
        )

    def verify_logger_running(self):
        """Verify tfw_logger is running"""
        ps_output = subprocess.check_output(["ps", "aux"], text=True)
        tfw_logger_count = len(
            [line for line in ps_output.split("\n") if "tfw_logger" in line and "grep" not in line]
        )
        self.assertGreaterEqual(tfw_logger_count, 1, "tfw_logger daemon should be running")

        # Verify mmap device exists
        self.assertTrue(os.path.exists("/dev/tempesta_mmap_log"), "Mmap device should exist")

    def verify_clickhouse_ready(self):
        """Verify ClickHouse is ready"""
        # Test connection
        test_result = self.clickhouse_client.query("SELECT 1")
        self.assertIsNotNone(test_result, "ClickHouse should be accessible")

        # Verify table exists
        table_exists = self.clickhouse_client.command("EXISTS TABLE access_log")
        self.assertTrue(table_exists, "access_log table should exist")

    def test_immediate_log_appearance(self):
        """
        This test demonstrates the original problem

        """
        self.verify_config_exists()
        self.start_all_services()
        self.verify_logger_running()
        self.verify_clickhouse_ready()

        client = self.get_client("deproxy")
        client.start()

        # Send request and measure time
        start_time = time.time()

        client.send_request(
            client.create_request(method="GET", headers=[]),
            expected_status_code="200",
            timeout=10,
        )

        # Add 100ms sleep to account for batching delay
        time.sleep(0.1)

        # Check for log appearance in ClickHouse
        max_wait = 0.2  # Reduce since we already waited 100ms
        found = False
        count = 0
        prev_count = 0
        check_count = 0

        while time.time() - start_time < max_wait:
            check_count += 1
            try:
                res = self.clickhouse_client.query("select count(*) from access_log")
                if res.result_rows:
                    count = res.result_rows[0][0]
                    if count > prev_count:
                        found = True
                        break
            except Exception as e:
                pass  # Continue checking
            time.sleep(0.01)

        elapsed = time.time() - start_time

        # Verify log appeared
        self.assertTrue(found, f"Log did not appear in ClickHouse within {max_wait}s")

        # Verify we got exactly one log
        self.assertEqual(count, 1, "Expected exactly one log entry")

    def test_multiple_requests(self):
        """
        Test that multiple requests are send
        """
        self.verify_config_exists()
        self.start_all_services()
        self.verify_logger_running()

        # Check initial row count
        try:
            res = self.clickhouse_client.query("select count(*) from access_log")
            initial_count = res.result_rows[0][0] if res.result_rows else 0
            pass
        except Exception as e:
            initial_count = 0

        client = self.get_client("deproxy")
        client.start()

        # Send multiple requests quickly
        num_requests = 5
        start_time = time.time()
        request_times = []

        for i in range(num_requests):
            req_start = time.time()
            client.send_request(
                client.create_request(method="GET", headers=[]),
                expected_status_code="200",
                timeout=10,
            )
            req_time = time.time() - req_start
            request_times.append(req_time)
            pass  # Request sent

        # Check that all logs appear quickly
        max_wait = 0.5  # 500ms for thorough debugging
        found_count = initial_count
        check_count = 0
        appearance_times = []

        while time.time() - start_time < max_wait:
            check_count += 1
            try:
                res = self.clickhouse_client.query("select count(*) from access_log")
                if res.result_rows:
                    current_count = res.result_rows[0][0]
                    if current_count > found_count:
                        new_logs = current_count - found_count
                        elapsed = time.time() - start_time
                        for i in range(new_logs):
                            appearance_times.append(elapsed)
                        found_count = current_count

                        if found_count - initial_count >= num_requests:
                            break
            except Exception as e:
                pass  # Continue checking
            time.sleep(0.01)

        elapsed = time.time() - start_time
        new_logs_count = found_count - initial_count

        # Verify all logs appeared
        self.assertEqual(
            new_logs_count, num_requests, f"Expected {num_requests} logs, found {new_logs_count}"
        )

        # Verify timing
        self.assertLess(elapsed, 0.2, f"Logs took {elapsed:.3f}s to appear, expected < 200ms")


class TestIssue2314(tester.TempestaTest):
    """Test for issue #2314 - missing logs during first second of startup"""

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        },
    ]

    tempesta = {
        "config": """
            listen 80;
            server ${server_ip}:8000;
            access_log dmesg;
        """
    }

    clients = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "addr": "${tempesta_ip}",
            "port": "80",
        }
    ]

    def test_startup_logs(self):
        """
        Test that documents issue #2314 - logs missing during first second of startup.
        This test verifies that logs appear in dmesg immediately after startup.
        """
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.start_all_clients()
        self.assertTrue(self.wait_all_connections())

        client = self.get_client("deproxy")
        client.start()

        # Send request immediately after startup
        client.send_request(
            request=client.create_request(method="GET", headers=[]),
            expected_status_code="200",
            timeout=10,
        )

        # Verify request appears in dmesg (this should work)
        request_in_dmesg = self.loggers.dmesg.find("GET / HTTP/1.1")
        self.assertTrue(request_in_dmesg, "Request should appear in dmesg")
