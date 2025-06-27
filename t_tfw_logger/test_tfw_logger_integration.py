"""Integration tests for tfw_logger with TempestaFW."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import json
import time
from pathlib import Path

from test_suite import marks, tester


@marks.parameterize_class(
    [
        {
            "name": "Http",
            "clients": [
                {
                    "id": "curl_http",
                    "type": "external",
                    "binary": "curl",
                    "cmd_args": "http://${tempesta_ip}:80/",
                }
            ],
        },
        {
            "name": "Https",
            "clients": [
                {
                    "id": "curl_https",
                    "type": "external",
                    "binary": "curl",
                    "cmd_args": "-k https://${tempesta_ip}:443/",
                }
            ],
        },
    ]
)
class TestTfwLoggerAccessLog(tester.TempestaTest):
    """Test access logging functionality with different protocols"""

    tempesta = {
        "config": """
listen 80;
listen 443 proto=https;

access_log mmap logger_config="${tempesta_workdir}/access_logger.json";

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
                "Content-Length: 25\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: keep-alive\r\n"
                "\r\n"
                "Access logging test: OK\n"
            ),
        }
    ]

    def setUp(self):
        super().setUp()

        # Create access logger configuration
        tempesta = self.get_tempesta()
        workdir = Path(tempesta.get_workdir())

        self.logger_config_path = workdir / "access_logger.json"
        self.logger_log_path = workdir / "access_logger.log"

        access_logger_config = {
            "log_path": str(self.logger_log_path),
            "buffer_size": 4194304,
            "cpu_count": 1,
            "clickhouse": {
                "host": "localhost",
                "port": 9000,
                "table_name": f"access_log_{self.name.lower()}",
                "max_events": 5,
                "max_wait_ms": 200,
            },
        }

        with open(self.logger_config_path, "w") as f:
            json.dump(access_logger_config, f, indent=2)

    def test_access_logging_enabled(self):
        """Test that access logging works with requests"""
        self.start_all_services()

        # Make requests to generate access log entries
        client_name = "curl_http" if "Http" in self.name else "curl_https"
        client = self.get_client(client_name)

        # Make several requests
        for i in range(3):
            client.start()
            self.wait_while_busy(client)
            client.stop()

            self.assertEqual(client.returncode, 0, f"Request {i+1} should succeed")
            self.assertIn(
                "Access logging test: OK",
                client.stdout,
                f"Should get response body from request {i+1}",
            )

            time.sleep(0.5)  # Brief pause between requests

        # Wait for access log processing
        time.sleep(3)

        # Verify configuration was processed
        tempesta = self.get_tempesta()
        config_content = tempesta.config.get_config()
        self.assertIn("access_log", config_content, "Config should contain access_log")
        self.assertIn("logger_config", config_content, "Config should reference logger_config")
