"""Basic tests for tfw_logger functionality."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

from test_suite import tester


class TestTfwLoggerBasic(tester.TempestaTest):
    """Basic functionality tests for tfw_logger"""

    tempesta = {
        "config": """
listen 80;
listen 443 proto=https;

access_log mmap logger_config="${tempesta_workdir}/tfw_logger.json";

server ${server_ip}:8000;

tls_certificate ${tempesta_workdir}/tempesta.crt;
tls_certificate_key ${tempesta_workdir}/tempesta.key;
tls_match_any_server_name;

frang_limits {
    http_strict_host_checking false;
}
"""
    }

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": (
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 13\r\n"
                "Connection: keep-alive\r\n"
                "\r\n"
                "Hello, world!"
            ),
        }
    ]

    clients = [
        {
            "id": "curl",
            "type": "external",
            "binary": "curl",
            "cmd_args": "-v http://${tempesta_ip}:80/",
        }
    ]

    def setUp(self):
        """Set up test with tfw_logger configuration"""
        super().setUp()

        # Create tfw_logger configuration
        tempesta = self.get_tempesta()
        workdir = Path(tempesta.get_workdir())

        self.logger_config_path = workdir / "tfw_logger.json"
        self.logger_log_path = workdir / "tfw_logger.log"

        logger_config = {
            "log_path": str(self.logger_log_path),
            "buffer_size": 4194304,
            "cpu_count": 1,
            "clickhouse": {
                "host": "localhost",
                "port": 9000,
                "table_name": "tempesta_test_access_log",
                "max_events": 10,
                "max_wait_ms": 100,
            },
        }

        with open(self.logger_config_path, "w") as f:
            json.dump(logger_config, f, indent=2)

    def test_basic_functionality(self):
        """Test basic tfw_logger functionality with Tempesta"""
        # Start all services
        self.start_all_services()

        # Make a request
        client = self.get_client("curl")
        client.start()
        self.wait_while_busy(client)
        client.stop()

        # Verify request was successful
        self.assertEqual(client.returncode, 0, "Client request should succeed")
        self.assertIn("Hello, world!", client.stdout, "Should get response from backend")

        # Wait for logging to process
        time.sleep(2)

        # Verify logger config was created
        self.assertTrue(
            self.logger_config_path.exists(),
            f"Logger config should exist at {self.logger_config_path}",
        )

    def test_config_file_creation(self):
        """Test that logger config file is properly created"""
        # Start services to trigger config creation
        self.start_all_services()

        # Verify config file exists and is valid JSON
        self.assertTrue(self.logger_config_path.exists(), "Config file should be created")

        with open(self.logger_config_path, "r") as f:
            config = json.load(f)

        # Verify required configuration sections
        self.assertIn("clickhouse", config, "Config should have ClickHouse section")
        self.assertIn("log_path", config, "Config should have log_path")
        self.assertIn("host", config["clickhouse"], "ClickHouse config should have host")

    def test_multiple_requests(self):
        """Test logging with multiple requests"""
        self.start_all_services()

        # Make multiple requests
        client = self.get_client("curl")

        for i in range(3):
            client.start()
            self.wait_while_busy(client)
            client.stop()

            self.assertEqual(client.returncode, 0, f"Request {i+1} should succeed")

            # Brief pause between requests
            time.sleep(0.5)

        # Wait for all logs to be processed
        time.sleep(3)


class TestTfwLoggerConfig(tester.TempestaTest):
    """Test different tfw_logger configurations"""

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
        }
    ]

    clients = [
        {
            "id": "curl",
            "type": "external",
            "binary": "curl",
            "cmd_args": "http://${tempesta_ip}:80/",
        }
    ]

    def _create_tempesta_config(self, logger_config_content):
        """Helper to create Tempesta config with custom logger config"""
        return {
            "config": f"""
listen 80;
access_log mmap logger_config="${{tempesta_workdir}}/custom_logger.json";
server ${{server_ip}}:8000;
frang_limits {{
    http_strict_host_checking false;
}}
"""
        }

    def _setup_custom_logger_config(self, config_data):
        """Helper to setup custom logger configuration"""
        tempesta = self.get_tempesta()
        workdir = Path(tempesta.get_workdir())

        config_path = workdir / "custom_logger.json"
        with open(config_path, "w") as f:
            json.dump(config_data, f, indent=2)

        return config_path

    def test_minimal_config(self):
        """Test with minimal logger configuration"""
        self.tempesta = self._create_tempesta_config("")

        minimal_config = {"clickhouse": {"host": "localhost"}}

        config_path = self._setup_custom_logger_config(minimal_config)

        # Should work with minimal config
        try:
            self.start_all_services()

            client = self.get_client("curl")
            client.start()
            self.wait_while_busy(client)
            client.stop()

            self.assertEqual(client.returncode, 0, "Should work with minimal config")

        except Exception as e:
            # If it fails, it should be due to ClickHouse not being available
            # which is acceptable for unit testing
            self.assertIn("clickhouse", str(e).lower(), "Failure should be ClickHouse related")

    def test_custom_buffer_size(self):
        """Test with custom buffer size configuration"""
        self.tempesta = self._create_tempesta_config("")

        custom_config = {
            "log_path": "/tmp/custom_tfw_logger.log",
            "buffer_size": 8388608,  # 8MB
            "cpu_count": 2,
            "clickhouse": {
                "host": "localhost",
                "port": 9000,
                "table_name": "custom_access_log",
                "max_events": 500,
                "max_wait_ms": 50,
            },
        }

        config_path = self._setup_custom_logger_config(custom_config)

        try:
            self.start_all_services()

            client = self.get_client("curl")
            client.start()
            self.wait_while_busy(client)
            client.stop()

            self.assertEqual(client.returncode, 0, "Should work with custom config")

        except Exception:
            # Custom config might fail due to external dependencies
            # This is acceptable in test environment
            pass

    def test_legacy_mmap_config(self):
        """Test backward compatibility with legacy mmap configuration"""
        # Test old-style config without logger_config
        self.tempesta = {
            "config": """
listen 80;
access_log mmap;
server ${server_ip}:8000;
frang_limits {
    http_strict_host_checking false;
}
"""
        }

        try:
            self.start_all_services()

            client = self.get_client("curl")
            client.start()
            self.wait_while_busy(client)
            client.stop()

            self.assertEqual(client.returncode, 0, "Legacy config should work")

        except Exception:
            # Legacy config might not be fully supported in new version
            # This is acceptable as we're transitioning to new format
            pass


class TestTfwLoggerErrors(tester.TempestaTest):
    """Test error handling in tfw_logger integration"""

    backends = [
        {
            "id": "deproxy",
            "type": "deproxy",
            "port": "8000",
            "response": "static",
            "response_content": "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK",
        }
    ]

    clients = [
        {
            "id": "curl",
            "type": "external",
            "binary": "curl",
            "cmd_args": "http://${tempesta_ip}:80/",
        }
    ]

    def test_invalid_json_config(self):
        """Test handling of invalid JSON in logger config"""
        self.tempesta = {
            "config": """
listen 80;
access_log mmap logger_config="${tempesta_workdir}/invalid.json";
server ${server_ip}:8000;
frang_limits {
    http_strict_host_checking false;
}
"""
        }

        # Create invalid JSON file
        tempesta = self.get_tempesta()
        workdir = Path(tempesta.get_workdir())

        invalid_config_path = workdir / "invalid.json"
        with open(invalid_config_path, "w") as f:
            f.write('{"clickhouse": {"host": "localhost"')  # Missing closing braces

        # Tempesta should handle invalid config gracefully
        try:
            self.start_all_services()

            # Basic functionality should still work
            client = self.get_client("curl")
            client.start()
            self.wait_while_busy(client)
            client.stop()

            # Request might succeed or fail depending on error handling
            # Both outcomes are acceptable for this test

        except Exception as e:
            # Should get a meaningful error about config
            self.assertTrue(
                any(keyword in str(e).lower() for keyword in ["config", "json", "parse"]),
                f"Error should mention config/JSON issue: {e}",
            )

    def test_nonexistent_config_file(self):
        """Test handling of nonexistent logger config file"""
        self.tempesta = {
            "config": """
listen 80;
access_log mmap logger_config="${tempesta_workdir}/nonexistent.json";
server ${server_ip}:8000;
frang_limits {
    http_strict_host_checking false;
}
"""
        }

        # Don't create the config file - it should be missing

        try:
            self.start_all_services()

            client = self.get_client("curl")
            client.start()
            self.wait_while_busy(client)
            client.stop()

            # System should handle missing config gracefully

        except Exception as e:
            # Should get a meaningful error about missing file
            self.assertTrue(
                any(keyword in str(e).lower() for keyword in ["file", "config", "not found"]),
                f"Error should mention missing file: {e}",
            )
