"""
Test for verifying that first log appear in ClickHouse immediately after startup
"""

import os
import subprocess
import time

from test_suite import tester

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

# Check if clickhouse_connect is available
try:
    import clickhouse_connect

    HAS_CLICKHOUSE = True
except ImportError:
    HAS_CLICKHOUSE = False


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
        if not HAS_CLICKHOUSE:
            self.skipTest("clickhouse_connect module not installed")

        super().setUp()

        # Create logger config
        import json

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

        # Clean up and recreate table with correct schema
        try:
            # Drop existing table if it exists
            self.clickhouse_client.command("DROP TABLE IF EXISTS access_log")

            # Create table with correct schema matching tfw_logger expectations
            create_table_query = """
            CREATE TABLE IF NOT EXISTS access_log (
                timestamp DateTime64(3, 'UTC'),
                address IPv6,
                method UInt8,
                version UInt8,
                status UInt16,
                response_content_length UInt32,
                response_time UInt32,
                vhost String,
                uri String,
                referer String,
                user_agent String,
                ja5t UInt64,
                ja5h UInt64,
                dropped_events UInt64
            ) ENGINE = MergeTree()
            ORDER BY timestamp
            """
            self.clickhouse_client.command(create_table_query)
            print("Created access_log table with correct schema")

        except Exception as e:
            # ClickHouse might not be available
            self.skipTest(f"ClickHouse not available: {e}")

    def tearDown(self):
        super().tearDown()
        # Clean up test config file
        import os

        try:
            os.remove("/tmp/tfw_logger_test.json")
        except:
            pass

    def run_pre_test_diagnostics(self):
        """Run pre-test diagnostics to check configuration"""
        print("\n=== PRE-TEST DIAGNOSTICS ===")

        # Check if config file was created
        if os.path.exists("/tmp/tfw_logger_test.json"):
            print("Config file exists at /tmp/tfw_logger_test.json")
            with open("/tmp/tfw_logger_test.json", "r") as f:
                print(f"Config content: {f.read()}")
        else:
            print("Config file NOT found at /tmp/tfw_logger_test.json")

    def run_post_start_diagnostics(self):
        """Run post-start diagnostics to check system state"""
        print("\n=== POST-START DIAGNOSTICS ===")

        # Check if tfw_logger is running
        try:
            ps_output = subprocess.check_output(["ps", "aux"], text=True)
            tfw_logger_procs = [
                line
                for line in ps_output.split("\n")
                if "tfw_logger" in line and "grep" not in line
            ]
            if tfw_logger_procs:
                print(f"tfw_logger is running ({len(tfw_logger_procs)} processes):")
                for proc in tfw_logger_procs:
                    print(f"  {proc}")
            else:
                print("tfw_logger is NOT running")
        except Exception as e:
            print(f"Error checking tfw_logger process: {e}")

        # Check if mmap device exists
        if os.path.exists("/dev/tempesta_mmap_log"):
            print("Mmap device exists at /dev/tempesta_mmap_log")
            try:
                stat_info = os.stat("/dev/tempesta_mmap_log")
                print(f"  Permissions: {oct(stat_info.st_mode)}")
            except Exception as e:
                print(f"  Error getting device info: {e}")
        else:
            print("Mmap device NOT found at /dev/tempesta_mmap_log")

        # Check daemon log
        if os.path.exists("/tmp/tfw_logger.log"):
            print("Daemon log exists at /tmp/tfw_logger.log")
            try:
                with open("/tmp/tfw_logger.log", "r") as f:
                    log_content = f.read()
                    print(f"  Last 5 lines:")
                    for line in log_content.strip().split("\n")[-5:]:
                        print(f"    {line}")
            except Exception as e:
                print(f"  Error reading log: {e}")
        else:
            print("Daemon log NOT found at /tmp/tfw_logger.log")

    def run_clickhouse_connectivity_test(self):
        """Test ClickHouse connectivity and table state"""
        print("\n=== CLICKHOUSE CONNECTIVITY ===")
        try:
            test_result = self.clickhouse_client.query("SELECT 1")
            print("ClickHouse connection successful")

            # Check if table exists
            table_exists = self.clickhouse_client.command("EXISTS TABLE access_log")
            print(f"  Table 'access_log' exists: {table_exists}")

            # Check current row count
            count_result = self.clickhouse_client.query("SELECT count(*) FROM access_log")
            current_count = count_result.result_rows[0][0] if count_result.result_rows else 0
            print(f"  Current rows in access_log: {current_count}")
        except Exception as e:
            print(f"ClickHouse error: {e}")

    def test_immediate_log_appearance(self):
        """
        This test demonstrates the original problem

        """
        # Pre-test diagnostics
        print("\n=== PRE-TEST DIAGNOSTICS ===")

        self.run_pre_test_diagnostics()

        self.start_all_services()

        self.run_post_start_diagnostics()
        self.run_clickhouse_connectivity_test()

        print("\n=== SENDING REQUEST ===")

        client = self.get_client("deproxy")
        client.start()

        # Send request and measure time
        start_time = time.time()

        client.send_request(
            client.create_request(method="GET", headers=[]),
            expected_status_code="200",
            timeout=10,
        )

        print(f"Request sent at: {start_time}")

        # Add 100ms sleep to account for batching delay
        time.sleep(0.1)

        print("\n=== CHECKING LOG APPEARANCE ===")

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
                        print(
                            f"  [{check_count}] Count increased from {prev_count} to {count} at {time.time() - start_time:.3f}s"
                        )
                        prev_count = count
                        found = True
                        break
                    elif check_count % 10 == 0:  # Print every 10th check
                        print(
                            f"  [{check_count}] Still {count} rows at {time.time() - start_time:.3f}s"
                        )
            except Exception as e:
                print(f"  ClickHouse query error at {time.time() - start_time:.3f}s: {e}")
            time.sleep(0.01)

        elapsed = time.time() - start_time

        print(f"\n=== RESULTS ===")
        print(f"Total elapsed time: {elapsed:.3f}s")
        print(f"Log found: {found}")
        print(f"Final count: {count}")
        print(f"Total checks: {check_count}")

        # Additional diagnostics if log not found
        if not found:
            print("\n=== ADDITIONAL DIAGNOSTICS (LOG NOT FOUND) ===")

            # Check daemon log again
            if os.path.exists("/tmp/tfw_logger.log"):
                try:
                    with open("/tmp/tfw_logger.log", "r") as f:
                        log_content = f.read()
                        print("Daemon log last 10 lines:")
                        for line in log_content.strip().split("\n")[-10:]:
                            print(f"  {line}")
                except Exception as e:
                    print(f"Error reading daemon log: {e}")

            # Check if tfw_logger is still running
            try:
                ps_output = subprocess.check_output(["ps", "aux"], text=True)
                tfw_logger_still_running = any(
                    "tfw_logger" in line and "grep" not in line for line in ps_output.split("\n")
                )
                print(f"tfw_logger still running: {tfw_logger_still_running}")
            except:
                pass

            # Try to get more info from ClickHouse
            try:
                # Check system.errors
                errors = self.clickhouse_client.query("SELECT * FROM system.errors WHERE value > 0")
                if errors.result_rows:
                    print("ClickHouse system errors:")
                    for row in errors.result_rows:
                        print(f"  {row}")
            except:
                pass

        # First check if log appeared at all
        self.assertTrue(
            found, f"Log did not appear in ClickHouse within {max_wait}s (elapsed: {elapsed:.3f}s)"
        )

        print(f"\n=== TIMING ANALYSIS ===")
        print(f"Log appeared in ClickHouse after {elapsed:.3f}s")

        # Calculate total time including our sleep
        total_time = elapsed + 0.1  # Add the 100ms sleep we did

        # Verify we got exactly one log
        self.assertEqual(count, 1, f"Expected 1 log, found {count}")

    def test_multiple_requests(self):
        """
        Test that multiple requests are send
        """
        print("\n=== MULTIPLE REQUESTS TEST ===")

        self.run_pre_test_diagnostics()

        self.start_all_services()

        self.run_post_start_diagnostics()

        # Check initial row count
        try:
            res = self.clickhouse_client.query("select count(*) from access_log")
            initial_count = res.result_rows[0][0] if res.result_rows else 0
            print(f"Initial ClickHouse row count: {initial_count}")
        except Exception as e:
            print(f"Error getting initial count: {e}")
            initial_count = 0

        print("\n=== SENDING MULTIPLE REQUESTS ===")

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
            print(f"  Request {i+1} sent, took {req_time:.3f}s")

        print(f"\nAll {num_requests} requests sent in {time.time() - start_time:.3f}s")
        print(f"Average request time: {sum(request_times)/len(request_times):.3f}s")

        print("\n=== CHECKING LOG APPEARANCE ===")

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
                        print(
                            f"  [{check_count}] +{new_logs} new logs (total: {current_count}) at {elapsed:.3f}s"
                        )
                        for i in range(new_logs):
                            appearance_times.append(elapsed)
                        found_count = current_count

                        # Check if we got all expected logs
                        if found_count - initial_count >= num_requests:
                            print(f"  All {num_requests} logs found!")
                            break
                    elif check_count % 10 == 0:
                        print(
                            f"  [{check_count}] Still {found_count - initial_count} new logs at {time.time() - start_time:.3f}s"
                        )
            except Exception as e:
                print(f"  ClickHouse query error at {time.time() - start_time:.3f}s: {e}")
            time.sleep(0.01)

        elapsed = time.time() - start_time
        new_logs_count = found_count - initial_count

        print(f"\n=== RESULTS ===")
        print(f"Total elapsed time: {elapsed:.3f}s")
        print(f"Initial count: {initial_count}")
        print(f"Final count: {found_count}")
        print(f"New logs: {new_logs_count}")
        print(f"Expected logs: {num_requests}")
        print(f"Total checks: {check_count}")

        if appearance_times:
            print(f"\n=== LOG APPEARANCE TIMING ===")
            print(f"First log appeared at: {appearance_times[0]:.3f}s")
            print(f"Last log appeared at: {appearance_times[-1]:.3f}s")
            print(f"Average appearance time: {sum(appearance_times)/len(appearance_times):.3f}s")

            print("\nPer-log timing (with max_events=1, each should be fast):")
            for i, t in enumerate(appearance_times[:num_requests]):
                print(f"  Log {i+1}: {t:.3f}s")

        # Additional diagnostics if not all logs found
        if new_logs_count < num_requests:
            print(f"\n=== ADDITIONAL DIAGNOSTICS (MISSING LOGS) ===")
            print(f"Missing {num_requests - new_logs_count} logs")

            # Check daemon log
            if os.path.exists("/tmp/tfw_logger.log"):
                try:
                    with open("/tmp/tfw_logger.log", "r") as f:
                        log_content = f.read()
                        print("\nDaemon log last 10 lines:")
                        for line in log_content.strip().split("\n")[-10:]:
                            print(f"  {line}")
                except Exception as e:
                    print(f"Error reading daemon log: {e}")

            # Try to get actual log entries
            try:
                logs = self.clickhouse_client.query(
                    "SELECT timestamp, method, status FROM access_log ORDER BY timestamp DESC LIMIT 10"
                )
                if logs.result_rows:
                    print("\nLast 10 ClickHouse entries:")
                    for row in logs.result_rows:
                        print(f"  {row}")
            except:
                pass

        # Assertions
        self.assertEqual(
            new_logs_count, num_requests, f"Expected {num_requests} logs, found {new_logs_count}"
        )

        # Timing analysis
        print(f"\n=== TIMING ANALYSIS ===")
        print(f"All {num_requests} logs appeared in {elapsed:.3f}s")

        if elapsed > 0.1:
            print(f"WARNING: Logs took {elapsed:.3f}s - slower than expected")
        else:
            print(f"SUCCESS: All logs appeared quickly ({elapsed:.3f}s)")

        self.assertLess(elapsed, 0.2, f"Logs took {elapsed:.3f}s to appear, expected < 200ms")
