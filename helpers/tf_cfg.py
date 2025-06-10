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


# Deprecated variable — kept temporarily for compatibility.
LOGGER = logging.getLogger("dprct")


class ConfigError(Exception):
    def __init__(self, msg):
        Exception.__init__(self, "Test configuration error: %s" % msg)


class TestFrameworkCfg:

    logger = LOGGER

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
        self._log_format = (
            "%(asctime)s.%(msecs)03d | %(levelname)8s | "
            "%(name)5s | %(module)s | %(lineno)03d | %(message)s"
        )

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
        HOST_IP, HOST_IPV6, REMOTE_IP, REMOTE_IPV6 should store as VM variables
        WEBSITE_USER and WEBSITE_PASSWORD should store as global jenkins variables.
        """
        host_ip = os.getenv("HOST_IP", None)
        host_ipv6 = os.getenv("HOST_IPV6", None)
        remote_ip = os.getenv("REMOTE_IP", None)
        remote_ipv6 = os.getenv("REMOTE_IPV6", None)
        website_user = os.getenv("WEBSITE_USER", None)
        website_password = os.getenv("WEBSITE_PASSWORD", None)

        if (
            host_ip is None
            or host_ipv6 is None
            or remote_ip is None
            or remote_ipv6 is None
            or website_user is None
            or website_password is None
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
        self.config["Server"]["website_user"] = website_user
        self.config["Server"]["website_password"] = website_password

        self.config["TFW_Logger"]["clickhouse_host"] = host_ip

    def defaults(self):
        self.config.read_dict(
            {
                "General": {
                    "ip": "127.0.0.1",
                    "ipv6": "::1",
                    "verbose": "0",
                    "workdir": "/tmp/host",
                    "duration": "10",
                    "concurrent_connections": "10",
                    "log_file": "tests_log.log",
                    "stress_threads": "2",
                    "stress_large_content_length": "65536",
                    "stress_requests_count": "100",
                    "stress_mtu": "1500",
                    "long_body_size": "500",
                    "memory_leak_threshold": "65536",
                },
                "Loggers": {
                    "dprct": "INFO",
                    "file_handler": "INFO",  # logs/test.log
                    "test": "INFO",  # test
                    "tcp": "INFO",  # tcp
                    "http": "INFO",  # http, https
                    "env": "INFO",  # env logs (subprocess calls, environment settitngs)
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
                    "unavailable_timeout": "300",
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
                    "unavailable_timeout": "300",
                    "interfaces": "",
                },
                "Server": {
                    "ip": "127.0.0.3",
                    "ipv6": "::1",
                    "hostname": "localhost",
                    "user": "root",
                    "port": "22",
                    "nginx": "nginx",
                    "workdir": "/tmp/nginx",
                    "resources": "/var/www/html/",
                    "aliases_interface": "enp1s0",
                    "aliases_base_ip": "192.168.123.2",
                    "max_workers": "16",
                    "keepalive_timeout": "60",
                    "keepalive_requests": "100",
                    "unavailable_timeout": "300",
                    "lxc_container_name": "tempesta-site-stage",
                    "website_user": os.getenv("WEBSITE_USER", ""),
                    "website_password": os.getenv("WEBSITE_PASSWORD", ""),
                },
                "TFW_Logger": {
                    "clickhouse_host": "127.0.0.1",
                    "clickhouse_port": "8123",
                    "clickhouse_username": "default",
                    "clickhouse_password": "",
                    "clickhouse_database": "default",
                    "daemon_log": "/tmp/tfw_logger.log",
                },
            }
        )

    def set_v_level(self, level):
        assert isinstance(level, int) or isinstance(level, str) and level.isdigit()
        self.config["General"]["Verbose"] = str(level)

    def set_duration(self, val):
        try:
            int(val)
        except ValueError:
            return False
        self.config["General"]["Duration"] = val
        return True

    def get(self, section, opt) -> str:
        try:
            return self.config[section][opt]
        except KeyError as r_exc:
            err_msg = f"Failed getting section `{section}` opt `{opt}`."
            self.logger.debug(err_msg)
            raise KeyError(err_msg) from r_exc

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
            rich_tracebacks=True,
            tracebacks_extra_lines=2,
        )
        stream_handler.setFormatter(
            logging.Formatter(fmt=self._log_format, datefmt=self._date_format)
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
        file_handler.setFormatter(
            logging.Formatter(fmt=self._log_format, datefmt=self._date_format)
        )

        # we use threads and should use queue in logs
        log_queue = queue.Queue()
        queue_handler = QueueHandler(log_queue)
        self.log_listner = QueueListener(log_queue, file_handler)

        return queue_handler

    def _set_log_levels(self, stream_handler: logging.Handler, queue_handler: logging.Handler):
        """
        Sets the log level for the file handler based on the configuration.
        Iterates over predefined loggers to set their log levels according to the configuration.
        """
        stream_handler_lvl = _DPRCT_LOG_LEVELS.get(int(self.config["General"]["Verbose"]))
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


def debug() -> bool:
    return int(cfg.get("General", "Verbose")) >= 3


def v_level():
    return int(cfg.get("General", "Verbose"))


_DPRCT_LOGGET = logging.getLogger("dprct")
_DPRCT_LOG_LEVELS = {
    0: logging.CRITICAL,
    1: logging.CRITICAL,
    2: logging.ERROR,
    3: logging.INFO,
    4: logging.INFO,
    5: logging.DEBUG,
    6: logging.DEBUG,
}


def dbg(level: int, msg: str, *args, **kwargs) -> None:
    _DPRCT_LOGGET.log(level=_DPRCT_LOG_LEVELS.get(level), msg=f"{msg}", *args, **kwargs)


def log_dmesg(node: "ANode", msg: str) -> None:
    """Forward a message to kernel log at given node."""
    try:
        node.run_cmd(f"echo '{msg}' > /dev/kmsg")
    except Exception as e:
        _DPRCT_LOGGET.error(f"Can not access node {node.type}: {str(e)}")


cfg = TestFrameworkCfg()


def populate_properties(user_properties):
    gen_properties = cfg.kvs.copy()
    user_properties.update(gen_properties)
