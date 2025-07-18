""" Controls node over SSH if remote, or via OS if local one. """

import abc
import multiprocessing.dummy as multiprocessing
import os
import re
import time
import typing

from framework import stateful
from helpers.clickhouse import ClickHouseFinder

from . import error, nginx, remote, tempesta, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

from .util import wait_until

# -------------------------------------------------------------------------------
# Clients
# -------------------------------------------------------------------------------


class Client(object, metaclass=abc.ABCMeta):
    """Base class for managing HTTP benchmark utilities.

    Command-line options can be added by appending `Client.options` list.
    Also see comment in `Client.add_option_file()` function.
    """

    def __init__(self, binary, uri="", ssl=False):
        """`uri` must be relative to server root.

        DO NOT format command line options in constructor! Instead format them
        in `form_command()` function. This would allow to update options until
        client will be started. See `Wrk` class for example
        """
        self.node = remote.client
        self.connections = int(tf_cfg.cfg.get("General", "concurrent_connections"))
        self.duration = int(tf_cfg.cfg.get("General", "Duration"))
        self.workdir = tf_cfg.cfg.get("Client", "workdir")
        self.ssl = ssl
        self.set_uri(uri)
        self.bin = tf_cfg.cfg.get_binary("Client", binary)
        self.cmd = ""
        self.clear_stats()
        # List of command-line options.
        self.options = []
        # List tuples (filename, content) to create corresponding files on
        # remote node.
        self.files = []
        # List of files to be removed from remote node after client finish.
        self.cleanup_files = []
        self.requests = 0
        self.rate = -1
        self.errors = 0
        self.statuses = {}

    def set_uri(self, uri):
        """For some clients uri is an optional parameter, e.g. for Siege.
        They use file with list of uris instead. Don't force clients to use
        uri field.
        """
        if uri:
            proto = "https://" if self.ssl else "http://"
            server_addr = tf_cfg.cfg.get("Tempesta", "ip")
            self.uri = "".join([proto, server_addr, uri])
        else:
            self.uri = ""

    def clear_stats(self):
        self.requests = 0
        self.rate = -1
        self.errors = 0

    def cleanup(self):
        for f in self.cleanup_files:
            self.node.remove_file(f)

    def copy_files(self):
        for name, content in self.files:
            self.node.copy_file(name, content)

    @abc.abstractmethod
    def parse_out(self, stdout, stderr):
        """Parse framework results."""
        print(stdout.decode("ascii"), stderr.decode("ascii"))
        return True

    def form_command(self):
        """Prepare run command for benchmark to run on remote node."""
        cmd = " ".join([self.bin] + self.options + [self.uri])
        return cmd

    def prepare(self):
        self.cmd = self.form_command()
        self.clear_stats()
        self.copy_files()
        return True

    def results(self):
        if self.rate == -1:
            self.rate = self.requests / self.duration
        return self.requests, self.errors, self.rate, self.statuses

    def add_option_file(self, option, filename, content):
        """Helper for using files as client options: normally file must be
        copied to remote node, present in command line as parameter and
        removed after client finish.
        """
        full_name = os.path.join(self.workdir, filename)
        self.files.append((filename, content))
        self.options.append("%s %s" % (option, full_name))
        self.cleanup_files.append(full_name)

    def set_user_agent(self, ua):
        self.options.append("-H 'User-Agent: %s'" % ua)


class Wrk(Client):
    """wrk - HTTP benchmark utility.

    Wrk counts statistics of bad socket operations: errors on opening, reading
    from and writing to sockets, error of HTTP message parsing and so on.
    If FAIL_ON_SOCK_ERR is set assert that none of such errors happened during
    test, otherwise print warning and count the errors as usual errors.
    """

    FAIL_ON_SOCK_ERR = False

    def __init__(self, threads=-1, uri="/", ssl=False, timeout=60):
        Client.__init__(self, binary="wrk", uri=uri, ssl=ssl)
        self.threads = threads
        self.script = ""
        self.timeout = timeout
        self.local_scriptdir = "".join([os.path.dirname(os.path.realpath(__file__)), "/../wrk/"])
        self.rs_content = self.read_local_script("results.lua")

    def read_local_script(self, filename):
        local_path = "".join([self.local_scriptdir, filename])
        local_script_path = os.path.abspath(local_path)
        assert os.path.isfile(local_script_path), "No script found: %s !" % local_script_path
        f = open(local_script_path, "r")
        content = f.read()
        f.close()
        return content

    def set_script(self, script, content=None):
        self.script = script + ".lua"

        if content == None:
            content = self.read_local_script(self.script)
        self.node.copy_file(self.script, "".join([content, self.rs_content]))

    def append_script_option(self):
        if not self.script:
            return
        script_path = self.workdir + "/" + self.script
        self.options.append("-s %s" % script_path)

    def form_command(self):
        self.options.append("-d %d" % self.duration)
        # At this moment threads equals user defined value or maximum theads
        # count for remote node.
        if self.threads == -1:
            self.threads = self.node.get_max_thread_count()
        if self.threads > self.connections:
            self.threads = self.connections
        if self.connections % self.threads != 0:
            nc = (self.connections // self.threads) * self.threads
        threads = self.threads if self.connections > 1 else 1
        self.options.append("-t %d" % threads)
        self.options.append("-c %d" % self.connections)
        self.options.append("--timeout %d" % self.timeout)
        self.append_script_option()
        return Client.form_command(self)

    def parse_out(self, stdout, stderr):
        m = re.search(r"(\d+) requests in ", stdout.decode())
        if m:
            self.requests = int(m.group(1))
        m = re.search(r"Non-2xx or 3xx responses: (\d+)", stdout.decode())
        if m:
            self.errors = int(m.group(1))
        m = re.search(r"Requests\/sec:\s+(\d+)", stdout.decode())
        if m:
            self.rate = int(m.group(1))
        matches = re.findall(r"Status (\d{3}) : (\d+) times", stdout.decode())
        for match in matches:
            status = match[0]
            status = int(status)
            amount = match[1]
            amount = int(amount)
            self.statuses[status] = amount

        sock_err_msg = "Socket errors on wrk. Too many concurrent connections?"
        m = re.search(r"(Socket errors:.+)", stdout.decode())
        if self.FAIL_ON_SOCK_ERR:
            assert not m, sock_err_msg
        if m:
            err_m = re.search(r"\w+ (\d+), \w+ (\d+), \w+ (\d+), \w+ (\d+)", m.group(1))
            self.errors += (
                int(err_m.group(1))
                + int(err_m.group(2))
                + int(err_m.group(3))
                + int(err_m.group(4))
            )
            # this is wrk-dependent results
            self.statuses["connect_error"] = int(err_m.group(1))
            self.statuses["read_error"] = int(err_m.group(2))
            self.statuses["write_error"] = int(err_m.group(3))
            self.statuses["timeout_error"] = int(err_m.group(4))
        return True


class Ab(Client):
    """Apache benchmark."""

    def __init__(self, uri="/", ssl=False):
        Client.__init__(self, "ab", uri=uri, ssl=ssl)

    def form_command(self):
        # Don't show progress.
        self.options.append("-q")
        self.options.append("-t %d" % self.duration)
        self.options.append("-c %d" % self.connections)
        return Client.form_command(self)

    def parse_out(self, stdout, stderr):
        m = re.search(r"Complete requests:\s+(\d+)", stdout)
        if m:
            self.requests = int(m.group(1))
        m = re.search(r"Non-2xx responses:\s+(\d+)", stdout)
        if m:
            self.errors = int(m.group(1))
        m = re.search(r"Failed requests:\s+(\d+)", stdout)
        if m:
            self.errors += int(m.group(1))
        return True


# -------------------------------------------------------------------------------
# Client helpers
# -------------------------------------------------------------------------------


def __clients_prepare(client):
    return client.prepare()


def __clients_run(client):
    return remote.client.run_cmd(client.cmd, timeout=(client.duration + 5))


def __clients_parse_output(args):
    client, (stdout, stderr) = args
    return client.parse_out(stdout, stderr)


def __clients_cleanup(client):
    return client.cleanup()


def clients_run_parallel(clients):
    if not clients:
        return

    pool = multiprocessing.Pool(len(clients))
    results = pool.map(__clients_prepare, clients)
    error.assertTrue(all(results), "Some HTTP clients failed on prepare stage!")

    results = pool.map(__clients_run, clients)

    parse_args = [(clients[i], results[i]) for i in range(len(clients))]
    pool.map(__clients_parse_output, parse_args)
    pool.map(__clients_cleanup, clients)


def clients_parallel_load(client, count=None):
    """Spawn @count processes without parsing output. Just make high load.
    Python is too slow to spawn multiple (>100) processes.
    """
    if count is None:
        count = min(int(tf_cfg.cfg.get("General", "concurrent_connections")), 1000)
    error.assertTrue(client.prepare())
    cmd = "seq %d | xargs -Iz -P1000 %s -q" % (count, client.cmd)

    pool = multiprocessing.Pool(2)
    results = pool.map(remote.client.run_cmd, [client.cmd, cmd])

    stdout, stderr = results[0]
    client.parse_out(stdout, stderr)
    client.cleanup()


# -------------------------------------------------------------------------------
# Tempesta
# -------------------------------------------------------------------------------
class Tempesta(stateful.Stateful):
    def __init__(self, vhost_auto=True):
        super().__init__(id_=remote.tempesta.host)
        self.node = remote.tempesta
        self.srcdir = tf_cfg.cfg.get("Tempesta", "srcdir")
        self.config = tempesta.Config(vhost_auto=vhost_auto)
        self.stats = tempesta.Stats()
        self.check_config = True
        self.clickhouse = ClickHouseFinder()
        self.stop_procedures = [
            self.stop_tempesta,
            self.config.remove_config_files,
            self.clickhouse.access_log_clear,
        ]

    def wait_while_logger_start(self, timeout: int = 5) -> bool:
        """
        Block thread until tfw_logger starts
        """
        if self.config.mmap is None:
            return True

        def wait():
            if not self.tfw_log_file_exists():
                return True

            if not self.clickhouse.find("worker threads started"):
                return True

            time.sleep(1)
            return False

        return wait_until(wait_cond=wait, timeout=timeout, poll_freq=0.1)

    @staticmethod
    def tfw_logger_signal(signal: typing.Literal["STOP", "CONT"]) -> None:
        remote.tempesta.run_cmd(f"kill -{signal} $(pidof tfw_logger)")

    @staticmethod
    def tfw_log_file_exists() -> bool:
        """
        Check if tfw log file exists
        """
        return remote.tempesta.exists(tf_cfg.cfg.get("TFW_Logger", "log_path"))

    def run_start(self):
        self.stats.clear()
        self._do_run(f"{self.srcdir}/scripts/tempesta.sh --start")

    def reload(self):
        """Live reconfiguration"""
        self._logger.info("Reconfiguring TempestaFW")
        self._do_run(f"{self.srcdir}/scripts/tempesta.sh --reload")

    def _do_run(self, cmd):
        cfg_content = self.config.get_config()

        self._logger.info(f"Tempesta config content:\n{cfg_content}")

        if self.check_config:
            assert cfg_content, "Tempesta config is empty."

        self.config.create_config_files()
        env = {"TFW_CFG_PATH": self.config.config_name, "TFW_CFG_TMPL": self.config.tmp_config_name}
        if tf_cfg.cfg.get("Tempesta", "interfaces"):
            env.update({"TFW_DEV": tf_cfg.cfg.get("Tempesta", "interfaces")})
        self.node.run_cmd(cmd, timeout=30, env=env)

    def stop_tempesta(self):
        cmd = "%s/scripts/tempesta.sh --stop" % self.srcdir
        self.node.run_cmd(cmd, timeout=30)

    def get_stats(self):
        cmd = "cat /proc/tempesta/perfstat"
        stdout, _ = self.node.run_cmd(cmd)
        self.stats.parse(stdout)

    def get_server_stats(self, path):
        cmd = "cat /proc/tempesta/servers/%s" % (path)
        return self.node.run_cmd(cmd)


class TempestaFI(Tempesta):
    """Tempesta class for testing with fault injection."""

    def __init__(self, stap_script, mod=False, mod_name="stap_tempesta", vhost_auto=True):
        Tempesta.__init__(self, vhost_auto=vhost_auto)
        self.stap = "".join([stap_script, ".stp"])

        self.stap_local = os.path.dirname(__file__) + "/../systemtap/" + self.stap
        self.stap_local = os.path.normpath(self.stap_local)

        self.module_stap = mod
        self.module_name = mod_name
        if self.module_stap:
            self.stap_msg = "Cannot %s stap %s Tempesta."
            self.modules_dir = "/lib/modules/$(uname -r)/custom/"
        else:
            self.stap_msg = "Cannot %s stap %s kernel."
        self.stop_procedures = [
            self.letout,
            self.letout_finish,
            self.stop_tempesta,
            self.remove_config,
        ]

    def inject_prepare(self):
        if self.module_stap:
            self.node.run_cmd("mkdir %s" % self.modules_dir)
            cmd = 'find %s/ -name "*.ko" | xargs cp -t %s'
            self.node.run_cmd(cmd % (self.srcdir, self.modules_dir))
            local = open(self.stap_local, "r")
            content = local.read()
            local.close()
            self.node.copy_file(self.stap, content)

    def inject(self):
        cmd = "stap -g -m %s -F %s/%s" % (self.module_name, self.workdir, self.stap)

        self.node.run_cmd(cmd, timeout=30)

    def letout(self):
        cmd = "rmmod %s" % self.module_name
        self.node.run_cmd(cmd, timeout=30)
        self.node.remove_file("".join([self.module_name, ".ko"]))

    def letout_finish(self):
        if self.module_stap:
            self.node.run_cmd("rm -r %s" % self.modules_dir)

    def run_start(self):
        Tempesta.run_start(self)
        self.inject_prepare()
        self.inject()


# -------------------------------------------------------------------------------
# Server
# -------------------------------------------------------------------------------


class Nginx(stateful.Stateful):
    def __init__(self, listen_port, workers=1):
        super().__init__(id_="")
        self.node = remote.server
        self.workdir = tf_cfg.cfg.get("Server", "workdir")
        self.ip = tf_cfg.cfg.get("Server", "ip")
        self.config = nginx.Config(self.workdir, listen_port, workers)
        self.clear_stats()
        # Configure number of connections used by TempestaFW.
        self.conns_n = tempesta.server_conns_default()
        self.active_conns = 0
        self.requests = 0
        self.stop_procedures = [self.stop_nginx, self.remove_config]

    def get_name(self):
        return ":".join([self.ip, str(self.config.port)])

    def run_start(self):
        self.clear_stats()
        # Copy nginx config to working directory on 'server' host.
        self.config.update_config()
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
        config_file = os.path.join(self.workdir, self.config.config_name)
        self.node.remove_file(config_file)

    def get_stats(self):
        """Nginx doesn't have counters for every virtual host. Spawn separate
        instances instead
        """
        self.stats_ask_times += 1
        # In default tests configuration Nginx status available on
        # `nginx_status` page.
        uri = "http://%s:%d/nginx_status" % (self.node.host, self.config.port)
        cmd = "curl %s" % uri
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

    def clear_stats(self):
        self.active_conns = 0
        self.requests = 0
        self.stats_ask_times = 0


# -------------------------------------------------------------------------------
# Server helpers
# -------------------------------------------------------------------------------


def servers_start(servers):
    for server in servers:
        server.start()


def servers_force_stop(servers):
    for server in servers:
        try:
            server.force_stop()
        except Exception:
            ...


def servers_stop(servers):
    for server in servers:
        try:
            server.stop()
        except Exception:
            ...


def servers_get_stats(servers):
    for server in servers:
        server.get_stats()


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
