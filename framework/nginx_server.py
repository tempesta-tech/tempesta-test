import os
import re
import time

from framework import stateful
from helpers import port_checks, remote, tempesta, tf_cfg, util
from helpers.util import fill_template

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2026 Tempesta Technologies, Inc."
__license__ = "GPL2"


class Nginx(stateful.Stateful):
    """The set of wrappers to manage Nginx, such as to start,
    stop, get statistics etc., from other Python classes."""

    class Config(object):
        def __init__(self, name, props):
            self.workdir = props["server_workdir"]
            pidname = self.workdir + "/nginx_" + name + ".pid"
            props.update({"pid": pidname})
            self.config = fill_template(props["config"], props)
            self.config_name = "nginx_%s.cfg" % name
            self.pidfile_name = pidname

    def __init__(self, id_, props):
        super().__init__(id_=id_)
        self.node = remote.server
        self.workdir = tf_cfg.cfg.get("Server", "workdir")
        self.config = self.Config(id_, props)

        # Configure number of connections used by TempestaFW.
        self.conns_n = tempesta.server_conns_default()
        self.name = id_
        self.status_uri = fill_template(props["status_uri"], props)
        self.stop_procedures = [self.stop_nginx, self.remove_config]
        self.weight = int(props["weight"]) if "weight" in props else None
        self.port_checker = port_checks.FreePortsChecker()

    def get_name(self):
        return self.name

    def clear_stats(self):
        super().clear_stats()
        self._active_conns = 0
        self._requests = 0
        self._stats_ask_times = 0

    def get_stats(self):
        """Nginx doesn't have counters for every virtual host. Spawn separate
        instances instead
        """
        self._stats_ask_times += 1
        out, _ = remote.client.run_cmd(f"curl {self.status_uri}")
        m = re.search(
            r"Active connections: (\d+) \n" r"server accepts handled requests\n \d+ \d+ (\d+)",
            out.decode(),
        )
        if m:
            # Current request increments active connections for nginx.
            self._active_conns = int(m.group(1)) - 1
            # Get rid of stats requests influence to statistics.
            self._requests = int(m.group(2)) - self._stats_ask_times

    def wait_for_connections(self, timeout=1):
        if self.state != stateful.STATE_STARTED:
            return False

        t0 = time.time()
        t = time.time()
        while t - t0 <= timeout:
            self.get_stats()
            if self.active_conns >= self.conns_n:
                return True
            time.sleep(0.001)  # to prevent redundant CPU usage
            t = time.time()
        return False

    def run_start(self):
        self.clear_stats()
        self.port_checker.check_ports_status()
        # Copy nginx config to working directory on 'server' host.
        self.node.copy_file(self.config.config_name, self.config.config)
        # Nginx forks on start, no background threads needed,
        # but it holds stderr open after demonisation.
        config_file = os.path.join(self.workdir, self.config.config_name)
        cmd = " ".join([tf_cfg.cfg.get("Server", "nginx"), "-c", config_file])
        self.node.run_cmd(cmd, is_blocking=False)

    def stop_nginx(self):
        pid_file = os.path.join(self.workdir, self.config.pidfile_name)
        cmd = " && ".join(
            [
                "[ -e '%s' ]" % pid_file,
                "pid=$(cat %s)" % pid_file,
                "kill -s TERM $pid",
                "while [ -e '/proc/$pid' ]; do sleep 1; done",
            ]
        )
        self.node.run_cmd(cmd, is_blocking=False)

    def remove_config(self):
        self._logger.info(f"Removing config.")
        config_file = os.path.join(self.workdir, self.config.config_name)
        self.node.remove_file(config_file)

    @property
    def active_conns(self) -> int:
        self.get_stats()
        return self._active_conns

    @property
    def requests(self) -> int:
        self.get_stats()
        return self._requests

    def wait_for_requests(self, n: int, timeout=1, strict=False, adjust_timeout=False) -> bool:
        """wait for the `n` number of responses to be received"""
        timeout_not_exceeded = util.wait_until(
            lambda: self.requests < n,
            timeout=timeout,
            abort_cond=lambda: self.state != stateful.STATE_STARTED,
            adjust_timeout=adjust_timeout,
        )
        if strict:
            assert (
                timeout_not_exceeded != False
            ), f"Timeout exceeded while waiting connection close: {timeout}"
        return timeout_not_exceeded


def nginx_srv_factory(server, name, tester):
    if "config" not in server.keys():
        return None
    return Nginx(name, server)
