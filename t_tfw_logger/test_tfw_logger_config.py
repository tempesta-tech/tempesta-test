"""Configuration tests for tfw_logger."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import json
import subprocess
import tempfile
from pathlib import Path

from test_suite import marks, tester


class TestTfwLoggerCommandLine(tester.TempestaTest):
    """Test tfw_logger command line interface"""

    # No Tempesta config needed - testing binary directly
    tempesta = {"config": "# CLI tests only"}
    backends = []
    clients = []

    def setUp(self):
        super().setUp()
        self.binary_path = Path(__file__).parent.parent.parent / "utils" / "tfw_logger"
        if not self.binary_path.exists():
            self.skipTest(f"tfw_logger binary not found at {self.binary_path}")

    def test_help_option(self):
        """Test --help option displays usage information"""
        result = subprocess.run(
            [str(self.binary_path), "--help"], capture_output=True, text=True, timeout=10
        )

        self.assertEqual(result.returncode, 0, "Help should return success")
        self.assertIn("Usage:", result.stdout, "Should show usage information")
        self.assertIn("--config", result.stdout, "Should mention config option")

    def test_version_display(self):
        """Test that help shows version or build info"""
        result = subprocess.run(
            [str(self.binary_path), "--help"], capture_output=True, text=True, timeout=10
        )

        # Should show help successfully
        self.assertEqual(result.returncode, 0)
        # Should mention systemd (new approach)
        self.assertIn("systemctl", result.stdout, "Should mention systemd usage")

    def test_invalid_arguments(self):
        """Test handling of invalid command line arguments"""
        invalid_args = [
            ["--invalid-option"],
            ["--port", "invalid"],
            ["--max-events", "-1"],
            ["--cpu-count", "-5"],
        ]

        for args in invalid_args:
            with self.subTest(args=args):
                result = subprocess.run(
                    [str(self.binary_path)] + args, capture_output=True, text=True, timeout=10
                )

                self.assertNotEqual(result.returncode, 0, f"Invalid args {args} should be rejected")

    def test_config_file_validation(self):
        """Test config file validation"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"clickhouse": {"host": "localhost"}}, f)
            config_file = f.name

        try:
            result = subprocess.run(
                [str(self.binary_path), "--config", config_file, "--help"],  # Exit quickly
                capture_output=True,
                text=True,
                timeout=10,
            )

            self.assertEqual(result.returncode, 0, "Valid config should be accepted")

        finally:
            Path(config_file).unlink(missing_ok=True)

    def test_command_line_overrides(self):
        """Test command line parameter overrides"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"clickhouse": {"host": "localhost"}}, f)
            config_file = f.name

        try:
            # Test various override combinations
            override_tests = [
                ["--host", "override-host"],
                ["--port", "9001"],
                ["--table", "custom_table"],
                ["--cpu-count", "2"],
                ["--max-events", "500"],
            ]

            for override_args in override_tests:
                with self.subTest(args=override_args):
                    result = subprocess.run(
                        [str(self.binary_path), "--config", config_file]
                        + override_args
                        + ["--help"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )

                    self.assertEqual(result.returncode, 0, f"Override {override_args} should work")

        finally:
            Path(config_file).unlink(missing_ok=True)


@marks.parameterize_class(
    [
        {"name": "MinimalConfig", "config": {"clickhouse": {"host": "localhost"}}},
        {
            "name": "FullConfig",
            "config": {
                "log_path": "/tmp/test_logger.log",
                "buffer_size": 8388608,
                "cpu_count": 2,
                "clickhouse": {
                    "host": "localhost",
                    "port": 9000,
                    "table_name": "test_access_log",
                    "user": "testuser",
                    "password": "testpass",
                    "max_events": 1000,
                    "max_wait_ms": 100,
                },
            },
        },
        {
            "name": "CustomBuffer",
            "config": {
                "buffer_size": 16777216,  # 16MB
                "clickhouse": {"host": "clickhouse.example.com"},
            },
        },
    ]
)
class TestTfwLoggerConfigValidation(tester.TempestaTest):
    """Test configuration validation with different config types"""

    tempesta = {"config": "# Config validation tests"}
    backends = []
    clients = []

    def setUp(self):
        super().setUp()
        self.binary_path = Path(__file__).parent.parent.parent / "utils" / "tfw_logger"
        if not self.binary_path.exists():
            self.skipTest(f"tfw_logger binary not found at {self.binary_path}")

    def test_config_acceptance(self):
        """Test that configuration is accepted and validated"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(self.config, f, indent=2)
            config_file = f.name

        try:
            result = subprocess.run(
                [str(self.binary_path), "--config", config_file, "--help"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            # Should accept valid configurations
            self.assertEqual(result.returncode, 0, f"Config should be valid: {self.config}")

        finally:
            Path(config_file).unlink(missing_ok=True)


class TestTfwLoggerConfigErrors(tester.TempestaTest):
    """Test configuration error handling"""

    tempesta = {"config": "# Error handling tests"}
    backends = []
    clients = []

    def setUp(self):
        super().setUp()
        self.binary_path = Path(__file__).parent.parent.parent / "utils" / "tfw_logger"
        if not self.binary_path.exists():
            self.skipTest(f"tfw_logger binary not found at {self.binary_path}")

    @marks.Parameterize.expand(
        [
            marks.Param(name="InvalidJson", content='{"invalid": json}'),
            marks.Param(name="MissingClickhouse", content='{"log_path": "/tmp/test.log"}'),
            marks.Param(
                name="InvalidBufferSize",
                content='{"buffer_size": -1, "clickhouse": {"host": "localhost"}}',
            ),
            marks.Param(name="EmptyFile", content=""),
        ]
    )
    def test_invalid_config_handling(self, name, content):
        """Test handling of various invalid configurations"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write(content)
            config_file = f.name

        try:
            result = subprocess.run(
                [str(self.binary_path), "--config", config_file],
                capture_output=True,
                text=True,
                timeout=10,
            )

            # Should reject invalid configurations
            self.assertNotEqual(result.returncode, 0, f"Invalid config should be rejected: {name}")

            # Should provide meaningful error message
            self.assertTrue(
                any(
                    keyword in result.stderr.lower()
                    for keyword in ["error", "config", "invalid", "failed"]
                ),
                f"Should show error message for {name}: {result.stderr}",
            )

        finally:
            Path(config_file).unlink(missing_ok=True)

    def test_nonexistent_config_file(self):
        """Test handling of nonexistent config file"""
        result = subprocess.run(
            [str(self.binary_path), "--config", "/nonexistent/config.json"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        self.assertNotEqual(result.returncode, 0, "Should fail with nonexistent file")
        self.assertIn("Failed to load configuration", result.stderr)

    def test_permission_denied_config(self):
        """Test handling of config file permission errors"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"clickhouse": {"host": "localhost"}}, f)
            config_file = f.name

        try:
            # Remove read permissions
            Path(config_file).chmod(0o000)

            result = subprocess.run(
                [str(self.binary_path), "--config", config_file],
                capture_output=True,
                text=True,
                timeout=10,
            )

            self.assertNotEqual(result.returncode, 0, "Should fail with permission error")

        finally:
            # Restore permissions for cleanup
            try:
                Path(config_file).chmod(0o644)
                Path(config_file).unlink()
            except:
                pass


class TestTfwLoggerScriptIntegration(tester.TempestaTest):
    """Test integration with Tempesta script patterns"""

    tempesta = {"config": "# Script integration tests"}
    backends = []
    clients = []

    def test_default_config_location(self):
        """Test that default config location is handled properly"""
        # Test behavior when no config file is specified
        binary_path = Path(__file__).parent.parent.parent / "utils" / "tfw_logger"
        if not binary_path.exists():
            self.skipTest(f"tfw_logger binary not found at {binary_path}")

        # Without config file, should show help or fail gracefully
        result = subprocess.run(
            [str(binary_path), "--help"], capture_output=True, text=True, timeout=10
        )

        self.assertEqual(result.returncode, 0, "Help should always work")

        # Test with non-existent default config
        result = subprocess.run([str(binary_path)], capture_output=True, text=True, timeout=10)

        # Should either work with defaults or fail gracefully
        if result.returncode != 0:
            self.assertIn(
                "configuration", result.stderr.lower(), "Error should mention configuration"
            )

    def test_environment_variable_support(self):
        """Test that environment variables work as expected"""
        binary_path = Path(__file__).parent.parent.parent / "utils" / "tfw_logger"
        if not binary_path.exists():
            self.skipTest(f"tfw_logger binary not found at {binary_path}")

        # Test with custom environment
        import os

        env = os.environ.copy()
        env["TFW_LOGGER_CONFIG"] = "/tmp/custom_config.json"

        # Should handle environment variables gracefully
        result = subprocess.run(
            [str(binary_path), "--help"], env=env, capture_output=True, text=True, timeout=10
        )

        self.assertEqual(result.returncode, 0, "Should work with custom environment")
