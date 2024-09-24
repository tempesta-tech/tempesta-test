""" Test framework configuration options.
"""

from __future__ import print_function, unicode_literals

import configparser
import os
import sys

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import logging
from typing import Union

from rich import pretty
from rich.logging import RichHandler

logger = logging.getLogger(__name__)


# we are adding custom levels to have initial 7 levels
# we may add custom methods to log class to have possibilities to cal custom method as default ones as `logger.debug`
TRACE = 5
FATAL = 60
logging.addLevelName(TRACE, "TRACE")
logging.addLevelName(FATAL, "FATAL")


log_levels = {
    0: FATAL,
    1: logging.CRITICAL,
    2: logging.ERROR,
    3: logging.WARNING,
    4: logging.INFO,
    5: logging.DEBUG,
    6: TRACE,
}


def bring_log_level(initial_lvl: Union[int, str]) -> int:
    """
    Bring log level to correct one for logging module based on initial one.

    Args:
        initial_lvl (Union[int, str]): old log level representation

    Returns:
        (int): leg level for logging module
    """
    return log_levels.get(int(initial_lvl), logging.DEBUG)


class ConfigError(Exception):
    def __init__(self, msg):
        Exception.__init__(self, "Test configuration error: %s" % msg)


class TestFrameworkCfg(object):

    logger = logger

    kvs = {}

    cfg_file = os.path.relpath(os.path.join(os.path.dirname(__file__), "..", "tests_config.ini"))

    def __init__(self, filename=None):
        if filename:
            self.cfg_file = filename
        self.defaults()
        self.cfg_err = None
        try:
            self.config.read(self.cfg_file)
            self.__fill_kvs()
        except:
            self.cfg_err = sys.exc_info()

        self.configure_logger()

    def __fill_kvs(self):
        for section in ["General", "Client", "Tempesta", "Server"]:
            cfg = self.config[section]
            for key in cfg.keys():
                id = "_".join([section.lower(), key])
                self.kvs[id] = cfg[key]

    def defaults(self):
        self.config = configparser.ConfigParser()
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
                "Client": {
                    "ip": "127.0.0.2",
                    "ipv6": "::1",
                    "hostname": "localhost",
                    "ab": "ab",
                    "wrk": "wrk",
                    "h2load": "h2load",
                    "tls-perf": "tls-perf",
                    "workdir": "/tmp/client",
                    "unavaliable_timeout": "300",
                },
                "Tempesta": {
                    "ip": "127.0.0.1",
                    "ipv6": "::1",
                    "hostname": "localhost",
                    "user": "root",
                    "port": "22",
                    "srcdir": "/root/tempesta",
                    "workdir": "/tmp/tempesta",
                    "config": "tempesta.conf",
                    "tmp_config": "tempesta_tmp.conf",
                    "unavaliable_timeout": "300",
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
                    "aliases_interface": "eth0",
                    "aliases_base_ip": "192.168.10.1",
                    "max_workers": "16",
                    "keepalive_timeout": "60",
                    "keepalive_requests": "100",
                    "unavaliable_timeout": "300",
                    "lxc_container_name": "tempesta-site-stage",
                    "website_user": "",
                    "website_password": "",
                },
            }
        )

    def set_v_level(self, level):
        assert isinstance(level, int) or isinstance(level, str) and level.isdigit()
        self.config["General"]["Verbose"] = str(level)
        self.logger.level = bring_log_level(level)

    def set_duration(self, val):
        try:
            int(val)
        except ValueError:
            return False
        self.config["General"]["Duration"] = val
        return True

    def get(self, section, opt) -> str:
        return self.config[section][opt]

    def set_option(self, section: str, opt: str, value: str) -> None:
        self.config[section][opt] = value

    def get_binary(self, section, binary):
        if self.config.has_option(section, binary):
            return self.config[section][binary]
        return binary

    def save_defaults(self):
        self.defaults()
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

    def configure_logger(self):
        """Configure a logger."""
        pretty.install()

        date_format = "%y-%m-%d %H:%M:%S"
        file_handler = logging.FileHandler(self.get("General", "log_file"))
        file_handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s.%(msecs)03d | %(levelname)s | %(message)s", datefmt=date_format
            )
        )
        stream_handler = RichHandler()
        stream_handler.setFormatter(
            logging.Formatter(fmt=" | %(message)s", datefmt=date_format + ".%f")
        )
        self.logger.addHandler(file_handler)
        self.logger.addHandler(stream_handler)

        # set default logging level as in config file,
        # otherwise a correct log level sets up during initialisation of cmd arguments after config is initialised.
        # default level for logging module is Warning
        self.logger.setLevel(
            bring_log_level(
                self.get("General", "verbose"),
            ),
        )


def debug() -> bool:
    return int(cfg.get("General", "Verbose")) >= 3


def v_level():
    return int(cfg.get("General", "Verbose"))


def dbg(level: int, msg: str, *args, **kwargs) -> None:
    logger.log(
        bring_log_level(level),
        msg,
        *args,
        **kwargs,
    )


def log_dmesg(node, msg) -> None:
    """Forward a message to kernel log at given node."""
    try:
        node.run_cmd('echo "%s" > /dev/kmsg' % msg)
    except Exception as e:
        dbg(2, "Can not access node %s: %s" % (node.type, str(e)))


cfg = TestFrameworkCfg()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
