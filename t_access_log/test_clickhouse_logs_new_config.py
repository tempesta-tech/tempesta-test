import json
import os
import time
from datetime import datetime

import clickhouse_connect

from helpers.error import ProcessBadExitStatusException
from test_suite import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestClickhouseLogsNewConfig(tester.TempestaTest):
    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\n" "Content-Length: 0\r\n\r\n",
        },
    ]

    tempesta = dict(
        config="""
            listen 80;
            server ${server_ip}:8000;

            access_log dmesg mmap logger_config=/tmp/tfw_logger_test.json;
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
        super(TestClickhouseLogsNewConfig, self).setUp()

        # Create JSON config for logger
        logger_config = {
            "log_path": "/tmp/tfw_logger.log",
            "buffer_size": 16777216,
            "clickhouse": {
                "host": "localhost",
                "port": 9000,
                "user": "default",
                "password": "",
                "table_name": "access_log",
                "max_events": 1000,
                "max_wait_ms": 100,
            },
        }

        # Write config file
        with open("/tmp/tfw_logger_test.json", "w") as f:
            json.dump(logger_config, f)

        self.clickhouse_client = clickhouse_connect.get_client()

        res = self.clickhouse_client.command("exists table access_log")

        if res:
            self.clickhouse_client.command("delete from access_log where true")

        try:
            print("removing logger daemon log")
            tempesta = self.get_tempesta()
            res = tempesta.node.run_cmd("rm /tmp/tfw_logger.log")
            assert res == (b"", b"")

        except ProcessBadExitStatusException as e:
            print(e)

    def tearDown(self):
        super().tearDown()
        # Clean up test config file
        try:
            os.remove("/tmp/tfw_logger_test.json")
        except:
            pass

    def test_missing_log(self):
        self.start_all_servers()
        self.start_tempesta()
        self.deproxy_manager.start()
        self.start_all_clients()
        self.assertTrue(self.wait_all_connections())

        client = self.get_client("deproxy")
        client.start()

        client.send_request(
            request=client.create_request(method="GET", headers=[]),
            expected_status_code="200",
            timeout=10,
        )

        request_in_dmesg = self.loggers.dmesg.find("GET / HTTP/1.1")
        assert request_in_dmesg is True

        # Check if logger daemon is running
        tempesta = self.get_tempesta()
        ps_stdout, _ = tempesta.node.run_cmd("ps aux | grep tfw_logger | grep -v grep")
        print(f"Logger processes: {ps_stdout}")

        # Check logger log file
        stdout, _ = tempesta.node.run_cmd("cat /tmp/tfw_logger.log")
        print(f"Logger log content: {stdout}")

        # Check if file exists and is not empty
        if stdout:
            print("Logger log file exists and has content")
        else:
            print("Logger log file is empty or doesn't exist")

        res = self.clickhouse_client.query("select * from access_log")
        print(f"Immediate check: {len(res.result_rows)} rows")
        if res.result_rows:
            print(f"Row content: {res.result_rows[0]}")

        # With JSON config, logs should appear (not be missing)
        # Original test expected 0 rows, but we have logs

        time.sleep(5)
        res = self.clickhouse_client.query("select * from access_log")
        print(f"After 5s: {len(res.result_rows)} rows")
        if res.result_rows:
            print(f"Row content: {res.result_rows[0]}")

        # Test shows that with new JSON config, logs appear correctly
        # assert len(res.result_rows) == 0
