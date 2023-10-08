"""
Controls node over SSH if remote, or via OS if local one.
The API is required to transparently handle both the cases - Tempesta and the
framework on the same node (developer tests case) or on separate machines (CI
case).
"""
from __future__ import print_function

import abc
import errno
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Union  # TODO: use | instead when we move to python3.10
from typing import Optional

import paramiko

import run_config

from . import error, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017 Tempesta Technologies, Inc."
__license__ = "GPL2"

# Don't remove files from remote node. Helpful for tests development.
DEBUG_FILES = False
# Default timeout for SSH sessions and command processing.
DEFAULT_TIMEOUT = 10


class Node(object, metaclass=abc.ABCMeta):
    def __init__(self, type, hostname, workdir):
        self.host = hostname
        self.workdir = workdir
        self.type = type

    def is_remote(self):
        return self.host != "localhost"

    @abc.abstractmethod
    def run_cmd(self, cmd, timeout=DEFAULT_TIMEOUT, ignore_stderr=False, err_msg="", env={}):
        pass

    @abc.abstractmethod
    def mkdir(self, path):
        pass

    @abc.abstractmethod
    def copy_file(self, filename, content):
        pass

    @abc.abstractmethod
    def copy_file_to_node(self, file, dest_dir):
        pass

    @abc.abstractmethod
    def remove_file(self, filename):
        pass

    @abc.abstractmethod
    def wait_available(self):
        pass


@dataclass
class CmdError(Exception):
    message: str
    stdout: Union[str, bytes]
    stderr: Union[str, bytes]
    returncode: int


class LocalNode(Node):
    def __init__(self, type, hostname, workdir):
        Node.__init__(self, type, hostname, workdir)

    def run_cmd(self, cmd, timeout=DEFAULT_TIMEOUT, ignore_stderr=False, err_msg="", env={}):
        tf_cfg.dbg(4, "\tRun command '%s' on host %s with environment %s" % (cmd, self.host, env))
        stdout = ""
        stderr = ""
        stderr_pipe = open(os.devnull, "w") if ignore_stderr else subprocess.PIPE
        # Popen() expects full environment
        env_full = {}
        env_full.update(os.environ)
        env_full.update(env)
        if run_config.SAVE_SECRETS and "curl" in cmd:
            env_full["SSLKEYLOGFILE"] = "./secrets.txt"

        with subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=stderr_pipe, env=env_full
        ) as p:
            try:
                # TODO #120: we should provide kill() and pid() interfaces to
                # let caller to determine if the command is executed and
                # when it's terminated and/or teriminate if when necessary.
                # Sometimes we also need to check whether a called program is
                # runnng long enough, e.g. tls-perf or wrk started in a parallel
                # thread didn't finish before all assumptions are checked in the
                # main thread.
                stdout, stderr = p.communicate(timeout=timeout)
                assert p.returncode == 0, "Cmd: '%s' return code is not 0 (%d)." % (
                    cmd,
                    p.returncode,
                )
            except subprocess.TimeoutExpired:
                p.kill()
                stdout, stderr = p.communicate()
                raise CmdError(
                    f"Cmd '{cmd}' got timed out (timeout value is {timeout})",
                    stdout,
                    stderr,
                    p.returncode,
                )
            except AssertionError:
                raise CmdError(
                    f"Сmd {cmd} exited with return code {p.returncode}",
                    stdout,
                    stderr,
                    p.returncode,
                )
        return stdout, stderr

    def mkdir(self, path):
        try:
            os.makedirs(path)
        except OSError:
            if not os.path.isdir(path):
                raise

    def copy_file(self, filename, content):
        # workdir will be ignored if an absolute filename is passed
        filename = os.path.join(self.workdir, filename)
        dirname = os.path.dirname(filename)

        # assume that workdir exists to avoid unnecessary actions
        if dirname != self.workdir:
            self.mkdir(dirname)

        with open(filename, "wt") as f:
            f.write(content)

    def copy_file_to_node(self, file, dest_dir):
        shutil.copy(file, dest_dir)

    def remove_file(self, filename):
        if DEBUG_FILES:
            return
        if os.path.isfile(filename):
            os.remove(filename)

    def wait_available(self):
        return True


@dataclass
class SSHCreds:
    host: str
    user: str
    pwd: Optional[str] = None  # If None host keys are used as auth method
    port: int = 22

    @staticmethod
    def from_cfg(cfg, section, prefix=""):
        host = cfg.maybe_get(section, f"{prefix}hostname")

        if not host:
            return None
        return SSHCreds(
            host=host,
            user=cfg.get(section, f"{prefix}user"),
            pwd=cfg.maybe_get(section, f"{prefix}password"),
            port=cfg.maybe_get(section, f"{prefix}port", int, default_val=22),
        )


class RemoteNode(Node):
    def __init__(
        self, type: str, workdir: str, creds: SSHCreds, jump_creds: Optional[SSHCreds] = None
    ):
        Node.__init__(self, type, creds.host, workdir)

        self.creds = creds
        self.jump_creds = jump_creds

        self.ssh = None
        self.jump_ssh = None
        self.connect()

    def connect(self):
        """Open SSH connection to node if remote. Returns False on SSH errors."""

        def do_connect(creds, sock=None):
            c = paramiko.SSHClient()
            if not creds.pwd:
                c.load_system_host_keys()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(
                creds.host, creds.port, creds.user, creds.pwd, sock=sock, timeout=DEFAULT_TIMEOUT
            )
            return c

        try:
            if self.jump_creds:
                self.jump_ssh = do_connect(self.jump_creds)
                sock = self.jump_ssh.get_transport().open_channel(
                    "direct-tcpip",
                    (self.creds.host, self.creds.port),
                    (self.jump_creds.host, self.jump_creds.port),
                )
            else:
                sock = None

            self.ssh = do_connect(self.creds, sock)
        except Exception as e:
            error.bug("Error connecting %s" % self.host)

    def close(self):
        """Release SSH connections without waiting for GC."""
        if self.ssh:
            self.ssh.close()
        if self.jump_ssh:
            self.jump_ssh.close()

    def run_cmd(self, cmd, timeout=DEFAULT_TIMEOUT, ignore_stderr=False, err_msg="", env={}):
        tf_cfg.dbg(4, "\tRun command '%s' on host %s with environment %s" % (cmd, self.host, env))
        stderr = ""
        stdout = ""
        # we could simply pass environment to exec_command(), but openssh' default
        # is to reject such environment variables, so pass them via env(1)
        if len(env) > 0:
            cmd = " ".join(["env", " ".join(["%s='%s'" % (k, v) for k, v in env.items()]), cmd])
            tf_cfg.dbg(4, "\tEffective command '%s' after injecting environment" % cmd)
        try:
            # TODO #120: the same as for LocalNode - provide an interface to check
            # whether the command is executed and when it's terminated and/or
            # kill it when necessary.
            _, out_f, err_f = self.ssh.exec_command(cmd, timeout=timeout)
            stdout = out_f.read()
            if not ignore_stderr:
                stderr = err_f.read()
            assert out_f.channel.recv_exit_status() == 0, "Return code is not 0."
        except Exception as e:
            if not err_msg:
                err_msg = "Error running command '%s' on %s" % (cmd, self.host)
            error.bug(err_msg, stdout=stdout, stderr=stderr)
        return stdout, stderr

    def mkdir(self, path):
        self.run_cmd("mkdir -p %s" % path)

    def copy_file(self, filename, content):
        # workdir will be ignored if an absolute filename is passed
        filename = os.path.join(self.workdir, filename)
        dirname = os.path.dirname(filename)

        # assume that workdir exists to avoid unnecessary actions
        if dirname != self.workdir:
            self.mkdir(dirname)

        try:
            sftp = self.ssh.open_sftp()
            sfile = sftp.file(filename, "wt", -1)
            sfile.write(content)
            sfile.flush()
            sftp.close()
        except Exception as e:
            error.bug(("Error copying file %s to %s" % (filename, self.host)))

    def copy_file_to_node(self, file, dest_dir):
        try:
            sftp = self.ssh.open_sftp()
            sftp.put(file, dest_dir)
            sftp.close()
        except Exception as e:
            error.bug(("Error copying file %s to %s" % (file, self.host)))

    def remove_file(self, filename):
        if DEBUG_FILES:
            return
        try:
            sftp = self.ssh.open_sftp()
            try:
                sftp.unlink(filename)
            except IOError as e:
                if e.errno != errno.ENOENT:
                    raise
            sftp.close()
        except Exception as e:
            error.bug(("Error removing file %s on %s" % (filename, self.host)))

    def wait_available(self):
        tf_cfg.dbg(3, "\tWaiting for %s node" % self.type)
        timeout = float(tf_cfg.cfg.get(self.type, "unavaliable_timeout"))
        t0 = time.time()
        while True:
            t = time.time()
            dt = t - t0
            tf_cfg.dbg(3, "\tAttempt to access node")
            if dt > timeout:
                tf_cfg.dbg(2, "Node %s is not available" % self.type)
                return False
            try:
                res, _ = self.run_cmd("echo -n check", timeout=1)
                tf_cfg.dbg(4, "Result = [%s]" % res)
                if res.decode() == "check":
                    tf_cfg.dbg(2, "Node %s is available" % self.type)
                    return True
            except Exception:
                try:
                    self.connect()
                except:
                    pass

            time.sleep(1)


def create_host_node():
    workdir = tf_cfg.cfg.get("General", "workdir")
    return LocalNode("General", "localhost", workdir)


def create_node(host):
    hostname = tf_cfg.cfg.get(host, "hostname")
    workdir = tf_cfg.cfg.get(host, "workdir")

    if hostname == "localhost":
        return LocalNode(host, hostname, workdir)

    creds = SSHCreds.from_cfg(tf_cfg.cfg, host)
    jump_creds = SSHCreds.from_cfg(tf_cfg.cfg, host, prefix="jump_")
    return RemoteNode(host, workdir, creds, jump_creds)


# -------------------------------------------------------------------------------
# Helper functions.
# -------------------------------------------------------------------------------


def get_max_thread_count(node):
    out, _ = node.run_cmd("grep -c processor /proc/cpuinfo")
    m = re.match(r"^(\d+)$", out.decode())
    if not m:
        return 1
    return int(m.group(1))


# -------------------------------------------------------------------------------
# Global accessible SSH/Local connections
# -------------------------------------------------------------------------------

client = None
tempesta = None
server = None
host = None


def connect():
    global client
    client = create_node("Client")

    global tempesta
    tempesta = create_node("Tempesta")

    global server
    server = create_node("Server")

    global host
    host = create_host_node()

    for node in [client, server, tempesta, host]:
        node.mkdir(node.workdir)


def wait_available():
    global client
    global server
    global tempesta
    return all(node.wait_available() for node in [client, server, tempesta])


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
