import dataclasses
import json
import os
import re
from typing import Optional

from helpers.cert_generator_x509 import CertGenerator

from . import error, remote, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


# Tempesta capabilities:
def servers_in_group():
    """Max servers in server group."""
    return 32


def server_conns_default():
    """Default connections to single upstream server."""
    return 32


def server_conns_max():
    """Maximum connections to single upstream server used in the tests.
    Tempesta has no maximum limit for the value.
    """
    return 32


def upstream_port_start_from():
    """Start value for upstream servers listen port. Just for convenience."""
    return 8000


# Version_info_cache
tfw_version = ""


def version():
    """TempestaFW current version. Defined in tempesta_fw.h:
    #define TFW_VERSION		"0.5.0-pre6"
    """
    global tfw_version
    if tfw_version:
        return tfw_version
    srcdir = tf_cfg.cfg.get("Tempesta", "srcdir")
    hdr_filename = "%s/fw/tempesta_fw.h" % (srcdir,)
    parse_cmd = r"grep TFW_VERSION | awk -F '[\" ]' '{printf $3}'"
    cmd = "cat %s | %s" % (hdr_filename, parse_cmd)
    version, _ = remote.tempesta.run_cmd(cmd=cmd)
    tfw_version = version.decode()
    error.assertTrue(tfw_version)
    return tfw_version


class Stats(object):
    """Parser for TempestaFW performance statistics (/proc/tempesta/perfstat)."""

    def __init__(self):
        self.clear()

    def clear(self):
        self.ss_pfl_hits = 0
        self.ss_pfl_misses = 0
        self.ss_wq_full = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.cl_msg_received = 0
        self.cl_msg_forwarded = 0
        self.cl_msg_served_from_cache = 0
        self.cl_msg_parsing_errors = 0
        self.cl_msg_filtered_out = 0
        self.cl_msg_other_errors = 0
        self.cl_conn_attempts = 0
        self.cl_established_connections = 0
        self.cl_conns_active = 0
        self.cl_rx_bytes = 0
        self.cl_priority_frame_exceeded = 0
        self.cl_rst_frame_exceeded = 0
        self.cl_settings_frame_exceeded = 0
        self.cl_ping_frame_exceeded = 0
        self.cl_wnd_update_frame_exceeded = 0
        self.srv_msg_received = 0
        self.srv_msg_forwarded = 0
        self.srv_msg_parsing_errors = 0
        self.srv_msg_filtered_out = 0
        self.srv_msg_other_errors = 0
        self.srv_conn_attempts = 0
        self.srv_established_connections = 0
        self.srv_conns_active = 0
        self.srv_rx_bytes = 0

    def parse(self, stats):
        self.ss_pfl_hits = self.parse_option(stats, "SS pfl hits")
        self.ss_pfl_misses = self.parse_option(stats, "SS pfl misses")
        self.wq_full = self.parse_option(stats, "SS work queue full")

        self.cache_hits = self.parse_option(stats, "Cache hits")
        self.cache_misses = self.parse_option(stats, "Cache misses")
        self.cache_objects = self.parse_option(stats, "Cache objects")
        self.cache_bytes = self.parse_option(stats, "Cache bytes")

        self.cl_msg_received = self.parse_option(stats, "Client messages received")
        self.cl_msg_forwarded = self.parse_option(stats, "Client messages forwarded")
        self.cl_msg_served_from_cache = self.parse_option(
            stats, "Client messages served from cache"
        )
        self.cl_msg_parsing_errors = self.parse_option(stats, "Client messages parsing errors")
        self.cl_msg_filtered_out = self.parse_option(stats, "Client messages filtered out")
        self.cl_msg_other_errors = self.parse_option(stats, "Client messages other errors")
        self.cl_conn_attempts = self.parse_option(stats, "Client connection attempts")
        self.cl_established_connections = self.parse_option(stats, "Client established connections")
        self.cl_conns_active = self.parse_option(stats, "Client connections active")
        self.cl_rx_bytes = self.parse_option(stats, "Client RX bytes")
        self.cl_priority_frame_exceeded = self.parse_option(
            stats, "Client priority frames number exceeded"
        )
        self.cl_rst_frame_exceeded = self.parse_option(stats, "Client rst frames number exceeded")
        self.cl_settings_frame_exceeded = self.parse_option(
            stats, "Client settings frames number exceeded"
        )
        self.cl_ping_frame_exceeded = self.parse_option(stats, "Client ping frames number exceeded")
        self.cl_wnd_update_frame_exceeded = self.parse_option(
            stats, "Client window update frames number exceeded"
        )

        self.srv_msg_received = self.parse_option(stats, "Server messages received")
        self.srv_msg_forwarded = self.parse_option(stats, "Server messages forwarded")
        self.srv_msg_parsing_errors = self.parse_option(stats, "Server messages parsing errors")
        self.srv_msg_filtered_out = self.parse_option(stats, "Server messages filtered out")
        self.srv_msg_other_errors = self.parse_option(stats, "Server messages other errors")
        self.srv_conn_attempts = self.parse_option(stats, "Server connection attempts")
        self.srv_established_connections = self.parse_option(
            stats, "Server established connections"
        )
        self.srv_conns_active = self.parse_option(stats, "Server connections active")
        self.srv_rx_bytes = self.parse_option(stats, "Server RX bytes")

        s = r"HTTP '(\d+)' code\s+: (\d+)"
        matches = re.findall(s.encode("ascii"), stats)
        self.health_statuses = {int(status): int(total) for status, total in matches}

    @staticmethod
    def parse_option(stats, name):
        s = r"%s\s+: (\d+)" % name
        m = re.search(s.encode("ascii"), stats)
        if m:
            return int(m.group(1))
        return -1


class ServerStats(object):
    def __init__(self, tempesta, sg_name, srv_ip, srv_port):
        self.tempesta = tempesta
        self.path = "%s/%s:%s" % (sg_name, srv_ip, srv_port)
        self.stats = None

    def collect(self):
        self.stats, _ = self.tempesta.get_server_stats(self.path)

    @property
    def server_health(self):
        self.collect()
        name = "HTTP availability"
        health = Stats.parse_option(self.stats, name)
        assert health >= 0, 'Cannot find "%s" in server stats: %s\n' % (name, self.stats)
        return health

    @property
    def health_statuses(self):
        pattern = r"HTTP '(\d+)' code\s+: \d+ \((\d+) total\)"
        matches = self._parse(pattern)
        return {int(status): int(total) for status, total in matches}

    @property
    def is_enable_health_monitor(self) -> bool:
        self.collect()
        record = "HTTP health monitor is enabled"
        return bool(Stats.parse_option(self.stats, record))

    @property
    def health_request_timeout(self) -> int:
        pattern = r"Time until next health check(?:ing)?\t:\s+\d+"
        result = self._parse(pattern)
        return int(result[0].split()[-1])

    @property
    def total_pinned_sessions(self) -> int:
        pattern = r"Total pinned sessions\t\t:\s+\d+"
        result = self._parse(pattern)
        return int(result[0].split()[-1])

    def _parse(self, pattern: str):
        self.collect()
        return re.findall(pattern.encode("ascii"), self.stats)


# -------------------------------------------------------------------------------
# Config Helpers
# -------------------------------------------------------------------------------


class ServerGroup(object):
    def __init__(self, name="default", sched="ratio", hm=None):
        self.name = name
        self.hm = hm
        self.implicit = name == "default"
        self.sched = sched
        self.servers = []
        # Server group options, inserted after servers.
        self.options = ""

    def add_server(self, ip, port, conns=server_conns_default()):
        error.assertTrue(conns <= server_conns_max())
        error.assertTrue(len(self.servers) < servers_in_group())
        conns_str = " conns_n=%d" % conns if (conns != server_conns_default()) else ""
        self.servers.append("server %s:%d%s;" % (ip, port, conns_str))

    def get_config(self):
        sg = ""
        if self.hm:
            self.options += " health %s;" % self.hm
        if (self.name == "default") and self.implicit:
            sg = "\n".join(["sched %s;" % self.sched] + self.servers + [self.options])
        else:
            sg = "\n".join(
                ["srv_group %s {" % self.name]
                + ["sched %s;" % self.sched]
                + self.servers
                + [self.options]
                + ["}"]
            )
        return sg


@dataclasses.dataclass
class TfwLogger(object):
    logger_config: str = tf_cfg.cfg.get("TFW_Logger", "logger_config")
    host: str = tf_cfg.cfg.get("TFW_Logger", "ip")
    user: str = tf_cfg.cfg.get("TFW_Logger", "clickhouse_username")
    password: str = tf_cfg.cfg.get("TFW_Logger", "clickhouse_password")
    max_events: int = 1000

    # The properties below must not be changed in the tests. These are global
    # test variables, and they must be changed in the main configuration.

    @property
    def database(self) -> str:
        return tf_cfg.cfg.get("TFW_Logger", "clickhouse_database")

    @property
    def table(self) -> str:
        return tf_cfg.cfg.get("TFW_Logger", "clickhouse_table")

    @property
    def log_path(self) -> str:
        return tf_cfg.cfg.get("TFW_Logger", "log_path")

    @property
    def tcp_port(self) -> int:
        return int(tf_cfg.cfg.get("TFW_Logger", "clickhouse_tcp_port"))


class Config(object):
    """Creates Tempesta config file."""

    def __init__(self, vhost_auto=True):
        self.server_groups = []
        self.__defconfig = ""
        self.vhost_auto_mode = vhost_auto
        self._logger_config: Optional[TfwLogger] = None

        self._workdir = remote.tempesta.workdir
        self.config_name = os.path.join(self._workdir, tf_cfg.cfg.get("Tempesta", "config"))
        self.tmp_config_name = os.path.join(self._workdir, tf_cfg.cfg.get("Tempesta", "tmp_config"))

        self._is_tls: bool = False
        self._tls_certificate: Optional[str] = None
        self._tls_certificate_key: Optional[str] = None
        self.mmap: Optional[str] = None

    @property
    def defconfig(self) -> str:
        return self.__defconfig

    @defconfig.setter
    def defconfig(self, config: str) -> None:
        self.set_defconfig(config, custom_cert=False)

    def create_config_files(self) -> None:
        remote.tempesta.copy_file(self.config_name, self.get_config())
        srcdir = tf_cfg.cfg.get("Tempesta", "srcdir")
        plugin_path = f"{srcdir}/logger/access_log_plugin/access_log.so"
        if self._logger_config is not None:
            logger_config = {
                "log_path": self._logger_config.log_path,
                "access_log": {
                    "plugin_path": plugin_path,
                    "host": self._logger_config.host,
                    "port": self._logger_config.tcp_port,
                    "user": self._logger_config.user,
                    "password": self._logger_config.password,
                    "db_name": self._logger_config.database,
                    "table_name": self._logger_config.table,
                    "max_events": self._logger_config.max_events,
                },
            }

            remote.tempesta.copy_file(
                filename=self._logger_config.logger_config,
                content=json.dumps(logger_config, ensure_ascii=False, indent=2),
            )

    def remove_config_files(self) -> None:
        remote.tempesta.remove_file(self.config_name)
        if self._logger_config is not None:
            remote.tempesta.remove_file(self._logger_config.logger_config)
            remote.tempesta.remove_file(self._logger_config.log_path)

    def find_sg(self, sg_name):
        for sg in self.server_groups:
            if sg.name == sg_name:
                return sg
        return None

    def remove_sg(self, name):
        sg = self.find_sg(name)
        error.assertFalse(sg is None)
        self.server_groups.remove(sg)

    def add_sg(self, new_sg):
        error.assertTrue(self.find_sg(new_sg.name) is None)
        self.server_groups.append(new_sg)

    def get_config(self) -> str:
        cfg = "\n".join([sg.get_config() for sg in self.server_groups] + [self.defconfig])
        return cfg

    def __generate_tls_certs(self, custom_cert: bool) -> None:
        """
        Parse the config string and generate x509 certificates if there are
        appropriate options in the config. The default cert generator creates
        only one certificate for the simplest Tempesta configuration - if you
        need per vhost certificates, multiple cerificates and/or custom
        certificate options, generate the certs on your own.
        """
        if custom_cert:
            return  # nothing to do for us, a caller takes care about certs

        if not self._is_tls:
            # don't create TLS cert\key
            return

        if self._is_tls and (self._tls_certificate is None and self._tls_certificate_key is None):
            raise

        cgen = CertGenerator(self._tls_certificate, self._tls_certificate_key, True)
        remote.tempesta.copy_file(self._tls_certificate, cgen.serialize_cert().decode())
        remote.tempesta.copy_file(self._tls_certificate_key, cgen.serialize_priv_key().decode())

    def __generate_clickhouse_config(self, tfw_config: Optional[TfwLogger] = None) -> None:
        if self.mmap is None or "mmap" not in self.mmap:
            return

        if tfw_config is not None:
            self._logger_config = tfw_config

        if self._logger_config is None:
            self._logger_config = TfwLogger(
                logger_config=re.search(r"logger_config=([^\s]+)", self.mmap).group(1)
            )

    def __process_config(self) -> None:
        _cfg = {}
        for l in self.defconfig.splitlines():
            # Skip the empty lines and comments
            if l.startswith("#") or l in ["", "{", "}"]:
                continue
            l = l.strip(" \t;")
            try:
                k, v = l.split(" ", 1)
            except ValueError:
                continue
            _cfg[k] = v

        self._is_tls = (
            True if any(proto in _cfg.get("listen", "") for proto in ["https", "h2"]) else False
        )
        self._tls_certificate = _cfg.get("tls_certificate", None)
        self._tls_certificate_key = _cfg.get("tls_certificate_key", None)
        if "mmap" in _cfg.get("events_log", ""):
            self.mmap = _cfg.get("events_log", "")

    def set_defconfig(
        self, config: str, custom_cert: bool = False, tfw_config: Optional[TfwLogger] = None
    ) -> None:
        if not config:
            return
        self.__defconfig = config
        self.__process_config()
        self.__generate_tls_certs(custom_cert)
        self.__generate_clickhouse_config(tfw_config)
