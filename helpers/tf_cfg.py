""" Test framework configuration options.
"""

from __future__ import print_function, unicode_literals

import configparser
import os
import sys

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import logging
import queue
from logging.handlers import QueueHandler, QueueListener, RotatingFileHandler
from typing import TYPE_CHECKING

from rich import pretty
from rich.logging import Console, RichHandler

if TYPE_CHECKING:
    from helpers.remote import ANode


test_logger = logging.LoggerAdapter(logging.getLogger("test"), extra={"service": f""})


class ConfigError(Exception):
    def __init__(self, msg):
        Exception.__init__(self, "Test configuration error: %s" % msg)


class TestFrameworkCfg:
    kvs = {}

    cfg_file = os.path.relpath(os.path.join(os.path.dirname(__file__), "..", "tests_config.ini"))

    def __init__(self, filename=None):

        if filename:
            self.cfg_file = filename

        self.config = configparser.ConfigParser()
        self.defaults()
        self.cfg_err = None
        self.log_listner = None
        self._date_format = "%H:%M:%S"

        try:
            self.config.read(self.cfg_file)
            self.__fill_kvs()
        except:
            self.cfg_err = sys.exc_info()

    def __fill_kvs(self):
        for section in ["General", "Client", "Tempesta", "Server", "TFW_Logger"]:
            cfg = self.config[section]
            for key in cfg.keys():
                id = "_".join([section.lower(), key])
                self.kvs[id] = cfg[key]

    def __update_config_for_remote_setup(self) -> None:
        """
        Update values for CI machines with remote setup.
        HOST_IP, HOST_IPV6, REMOTE_IP, REMOTE_IPV6 should store as VM variables.
        """
        host_ip = os.getenv("HOST_IP", None)
        host_ipv6 = os.getenv("HOST_IPV6", None)
        remote_ip = os.getenv("REMOTE_IP", None)
        remote_ipv6 = os.getenv("REMOTE_IPV6", None)

        if (
            host_ip is None
            or host_ipv6 is None
            or remote_ip is None
            or remote_ipv6 is None
        ):
            logging.critical(
                "IP and IPv6 addresses, login and password for tempesta-tech.com "
                "must be declared in the environment variables",
            )
            sys.exit(-1)

        self.config["General"]["ip"] = remote_ip
        self.config["General"]["ipv6"] = remote_ipv6

        self.config["Client"]["ip"] = remote_ip
        self.config["Client"]["ipv6"] = remote_ipv6

        self.config["Tempesta"]["ip"] = host_ip
        self.config["Tempesta"]["ipv6"] = host_ipv6
        self.config["Tempesta"]["hostname"] = host_ip

        self.config["Server"]["ip"] = remote_ip
        self.config["Server"]["ipv6"] = remote_ipv6

        self.config["TFW_Logger"]["clickhouse_host"] = host_ip

    def defaults(self):
        self.config.read_dict(
            {
                "General": {
                    "duration": "10",
                    "concurrent_connections": "100",
                    "log_file": "tests_log.log",
                    "stress_threads": "2",
                    "stress_large_content_length": "131072",
                    "stress_requests_count": "100",
                    "stress_mtu": "1500",
                    "long_body_size": "500",
                    "memory_leak_threshold": "131072",
                    "unavailable_timeout": "300",
                },
                "Loggers": {
                    "stream_handler": "CRITICAL",
                    "file_handler": "INFO",  # logs/test.log
                    "test": "INFO",  # test
                    "tcp": "INFO",  # tcp
                    "http": "INFO",  # http, https
                    "env": "INFO",  # env logs (subprocess calls, environment settings)
                    "service": "INFO",  # service logs (statefull, etc.)
                    "dap": "INFO",  # DeproxyAutoParser
                },
                "Client": {
                    "ip": "127.0.0.2",
                    "ipv6": "::1",
                    "hostname": "localhost",
                    "ab": "ab",
                    "wrk": "wrk",
                    "h2load": "h2load",
                    "tls-perf": "tls-perf",
                    "workdir": "/tmp/client",
                },
                "Tempesta": {
                    "ip": "127.0.0.1",
                    "ipv6": "::1",
                    "hostname": "localhost",
                    "user": "root",
                    "port": "22",
                    "ssh_key": "",
                    "srcdir": "/root/tempesta",
                    "workdir": "/tmp/tempesta",
                    "config": "tempesta.conf",
                    "tmp_config": "tempesta_tmp.conf",
                    "interfaces": "",
                },
                "Server": {
                    "ip": "127.0.0.3",
                    "ipv6": "::1",
                    "hostname": "localhost",
                    "nginx": "nginx",
                    "workdir": "/tmp/nginx",
                    "resources": "/var/www/html/",
                    "aliases_interface": "enp1s0",
                    "aliases_base_ip": "192.168.123.2",
                    "max_workers": "16",
                    "keepalive_timeout": "60",
                    "keepalive_requests": "100",
                },
                "TFW_Logger": {
                    "ip": os.getenv("CLICKHOUSE_IP", "127.0.0.1"),
                    "hostname": os.getenv("CLICKHOUSE_IP", "localhost"),
                    "user": "root",
                    "port": "22",
                    "ssh_key": "",
                    "workdir": "/tmp/tfw_logger",
                    "clickhouse_http_port": os.getenv("CLICKHOUSE_HTTP_PORT", "8123"),
                    "clickhouse_tcp_port": os.getenv("CLICKHOUSE_TCP_PORT", "9000"),
                    "clickhouse_username": os.getenv("CLICKHOUSE_USERNAME", "default"),
                    "clickhouse_password": os.getenv("CLICKHOUSE_PASSWORD", ""),
                    "clickhouse_database": os.getenv("CLICKHOUSE_DATABASE", "default"),
                    "clickhouse_table": os.getenv("CLICKHOUSE_TABLE", "access_log"),
                    "log_path": "/tmp/tfw_logger.log",
                    "logger_config": "/tmp/tfw_logger.json",
                },
            }
        )

    def set_duration(self, val):
        try:
            int(val)
        except ValueError:
            return False
        self.config["General"]["Duration"] = val
        return True

    def get(self, section, opt) -> str:
        try:
            result = self.config[section][opt]
            test_logger.debug(f"Got config param {opt}={result} for '{section}'")
            return result
        except KeyError:
            err_msg = f"Failed getting section `{section}` opt `{opt}`."
            test_logger.critical(err_msg)
            raise KeyError(err_msg) from None

    def set_option(self, section: str, opt: str, value: str) -> None:
        self.config[section][opt] = value

    def get_binary(self, section, binary):
        if self.config.has_option(section, binary):
            return self.config[section][binary]
        return binary

    def save_defaults(self, setup: str):
        self.defaults()
        if setup == "remote":
            self.__update_config_for_remote_setup()
        with open(self.cfg_file, "w") as configfile:
            self.config.write(configfile)
        print("Default configuration saved to %s" % self.cfg_file)

    def check(self):
        if self.cfg_err is not None:
            msg = 'unable to read "%s" (%s: %s)' % (
                self.cfg_file,
                self.cfg_err[0].__name__,
                self.cfg_err[1],
            )
            raise ConfigError(msg).with_traceback(self.cfg_err[2])

        # normalize paths
        normalize = [
            ("Client", "workdir"),
            ("Tempesta", "workdir"),
            ("Tempesta", "srcdir"),
            ("Server", "workdir"),
        ]
        for item in normalize:
            self.config[item[0]][item[1]] = os.path.normpath(self.config[item[0]][item[1]])

        # TODO: check configuration options
        client_hostname = self.config["Client"]["hostname"]
        if client_hostname != "localhost":
            msg = 'running clients on a remote host "%s" is not supported' % client_hostname
            raise ConfigError(msg)

    def _create_stream_handler(self) -> logging.Handler:
        """
        Integrates RichHandler for enhanced console logging.
        """
        # console handlers
        pretty.install()
        stream_handler = RichHandler(
            console=Console(width=180, color_system="256"),
            show_level=True,
            show_path=True,
            rich_tracebacks=True,
            tracebacks_extra_lines=2,
        )
        stream_handler.setFormatter(
            logging.Formatter(
                fmt=("%(asctime)s.%(msecs)03d | %(name)7s | %(service)39s | %(message)s"),
                datefmt=self._date_format,
            )
        )
        return stream_handler

    def _create_queue_handler(self) -> logging.Handler:
        """
        Sets up a rotating file handler for log files with a maximum of 10 backups.
        """
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)

        # file handler
        log_file = os.path.join(log_dir, "test.log")
        file_handler = RotatingFileHandler(log_file, maxBytes=0, backupCount=10)
        file_handler.doRollover()

        # we use threads and should use queue in logs
        log_queue = queue.Queue()
        queue_handler = QueueHandler(log_queue)
        queue_handler.setFormatter(
            logging.Formatter(
                fmt=(
                    "%(asctime)s.%(msecs)03d | %(levelname)8s | "
                    "%(name)7s | %(module)19s | %(lineno)03d | %(service)39s | %(message)s"
                ),
                datefmt=self._date_format,
            )
        )
        self.log_listner = QueueListener(log_queue, file_handler)

        return queue_handler

    def _set_log_levels(self, stream_handler: logging.Handler, queue_handler: logging.Handler):
        """
        Sets the log level for the file handler based on the configuration.
        Iterates over predefined loggers to set their log levels according to the configuration.
        """
        stream_handler_lvl = logging._nameToLevel.get(self.config["Loggers"]["stream_handler"])
        file_handler_lvl = logging._nameToLevel.get(self.config["Loggers"]["file_handler"])

        stream_handler.setLevel(stream_handler_lvl)
        queue_handler.setLevel(file_handler_lvl)

        logging.basicConfig(level=logging.CRITICAL, handlers=[queue_handler, stream_handler])

        for name, value in self.config["Loggers"].items():
            value = logging._nameToLevel.get(value)
            # We SHOULD NOT set a low level for loggers if handlers have a high level
            # because it has a high effect on performance.
            if value < min([file_handler_lvl, stream_handler_lvl]):
                value = min([file_handler_lvl, stream_handler_lvl])
            logging.getLogger(name).setLevel(value)

    def configure_logger(self):
        """Configures the logging setup for the test framework."""
        self._set_log_levels(
            self._create_stream_handler(),
            self._create_queue_handler(),
        )
        self.log_listner.start()


def log_dmesg(node: "ANode", msg: str) -> None:
    """Forward a message to kernel log at given node."""
    try:
        node.run_cmd(f'echo "{msg}" > /dev/kmsg')
    except Exception as e:
        test_logger.error(f"Can not access node {node.type}: {str(e)}")


cfg = TestFrameworkCfg()


def populate_properties(user_properties):
    gen_properties = cfg.kvs.copy()
    user_properties.update(gen_properties)
