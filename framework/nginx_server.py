import os
import re
import time

from framework import stateful
from helpers import port_checks, remote, tempesta, tf_cfg
from helpers.util import fill_template

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
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
        self.active_conns = 0
        self.requests = 0
        self.name = id_
        self.status_uri = fill_template(props["status_uri"], props)
        self.stop_procedures = [self.stop_nginx, self.remove_config]
        self.weight = int(props["weight"]) if "weight" in props else None
        self.port_checker = port_checks.FreePortsChecker()

        self.clear_stats()

    def get_name(self):
        return self.name

    def clear_stats(self):
        self.active_conns = 0
        self.requests = 0
        self.stats_ask_times = 0

    def get_stats(self):
        """Nginx doesn't have counters for every virtual host. Spawn separate
        instances instead
        """
        self.stats_ask_times += 1
        # In default tests configuration Nginx status available on
        # `nginx_status` page.
        cmd = "curl %s" % self.status_uri
        out, _ = remote.client.run_cmd(cmd)
        m = re.search(
            r"Active connections: (\d+) \n" r"server accepts handled requests\n \d+ \d+ (\d+)",
            out.decode(),
        )
        if m:
            # Current request increments active connections for nginx.
            self.active_conns = int(m.group(1)) - 1
            # Get rid of stats requests influence to statistics.
            self.requests = int(m.group(2)) - self.stats_ask_times

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


def nginx_srv_factory(server, name, tester):
    if "config" not in server.keys():
        return None
    return Nginx(name, server)
