import multiprocessing
import os
import re

from helpers import control, remote, stateful, tf_cfg
from helpers.util import fill_template

from . import client

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018 Tempesta Technologies, Inc."
__license__ = "GPL2"


class Wrk(client.Client):
    """The set of wrappers to manage Wrk, such as to start,
    stop, get statistics etc., from other Python classes."""

    FAIL_ON_SOCK_ERR = False

    def __init__(self, threads=-1, timeout=60, **kwargs):
        client.Client.__init__(self, "wrk", **kwargs)
        self.local_scriptdir = "".join([os.path.dirname(os.path.realpath(__file__)), "/../wrk/"])
        self.rs_content = self.read_local_script("results.lua")
        self.timeout = timeout
        self.threads = threads
        self.script = ""

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
            self.threads = remote.get_max_thread_count(self.node)
        if self.threads > self.connections:
            self.threads = self.connections
        threads = self.threads if self.connections > 1 else 1
        self.options.append("-t %d" % threads)
        self.options.append("-c %d" % self.connections)
        self.options.append("--timeout %d" % self.timeout)
        self.append_script_option()
        return client.Client.form_command(self)

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
            tf_cfg.dbg(1, "WARNING! %s" % sock_err_msg)
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
