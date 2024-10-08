"""
Module to work with nodes: local and remote(via SSH).

The API is required to transparently handle both cases - Tempesta and the framework
on the same node (developer test case), or on separate machines (CI case).
"""
from __future__ import print_function

import abc
import errno
import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Optional, Union  # TODO: use | instead when we move to python3.10

import paramiko

import run_config

from helpers import error, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

LOGGER = logging.getLogger(__name__)

# Don't remove files from remote node. Helpful for tests development.
DEBUG_FILES = False
# Default timeout for SSH sessions and command processing.
DEFAULT_TIMEOUT = 10


class INode(object, metaclass=abc.ABCMeta):
    """Node interfaces."""

    LOGGER = LOGGER

    DEBUG_FILES = DEBUG_FILES

    def __init__(self, ntype: str, hostname: str, workdir: str, *args, **kwargs):
        """
        Init class instance.

        Args:
            ntype (str): node type
            hostname (str): node hostname
            workdir (str): node workdir
            args: extra arguments
            kwargs: extra key arguments
        """
        self.host = hostname
        self.workdir = workdir
        self.type = ntype

    @abc.abstractmethod
    def run_cmd(self, cmd: str, timeout: int = DEFAULT_TIMEOUT, env: Optional[dict] = None) -> (bytes, bytes):
        """
        Run command.

        Args:
            cmd (str): command to run
            timeout (int): command running timeout
            env (Optional[dict]): environment variables to execute command with

        Returns:
            (tuple[bytes, bytes]): stdout, stderr
        """

    @abc.abstractmethod
    def mkdir(self, path: str):
        """
        Create directory on a node.

        Args:
            path (str): path to directory to create
        """

    @abc.abstractmethod
    def copy_file(self, filename: str, content: Any):
        """
        Copy file.

        Args:
            filename (str): filename to copy
            content (Any): content to copy
        """

    @abc.abstractmethod
    def remove_file(self, filename: str):
        """
        Remove file.

        Args:
            filename (str): filename to remove
        """

    @abc.abstractmethod
    def wait_available(self) -> bool:
        """
        Wait for a node.

        Returns:
            (bool): True, if ready
        """

    @abc.abstractmethod
    def get_max_thread_count(self) -> int:
        """
        Get number of max threads on a node.

        Returns:
            (int) number of max threads
        """


@dataclass
class CmdError(Exception):
    message: str
    stdout: Union[str, bytes]
    stderr: Union[str, bytes]
    returncode: int


class LocalNode(INode):
    """Local node class."""

    def run_cmd(self, cmd: str, timeout: int = DEFAULT_TIMEOUT, env: Optional[dict] = None) -> tuple[bytes, bytes]:
        """
        Run command.

        Args:
            cmd (str): command to run
            timeout (int): command running timeout
            env (Optional[dict]): environment variables to execute command with

        Returns:
            (tuple[bytes, bytes]): stdout, stderr

        Raises:
            error.ProcessBadExitStatusException: if an exit code is not 0(zero)
            error.CommandExecutionException: if something happened during the execution
            error.ProcessKilledException: if a process was killed
        """
        self.LOGGER.info("Run command '{0}' on host {1} with environment {2}".format(cmd, self.host, env))

        # Popen() expects full environment
        env_full = os.environ.copy()
        if env:
            env_full.update(env)
        if run_config.SAVE_SECRETS and "curl" in cmd:
            env_full["SSLKEYLOGFILE"] = "./secrets.txt"

        self.LOGGER.debug("All environment variables after updating: {0}".format(env_full))

        with subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env_full
        ) as current_proc:
            try:
                # TODO #120: we should provide kill() and pid() interfaces to
                # let caller to determine if the command is executed and
                # when it's terminated and/or teriminate if when necessary.
                # Sometimes we also need to check whether a called program is
                # runnng long enough, e.g. tls-perf or wrk started in a parallel
                # thread didn't finish before all assumptions are checked in the
                # main thread.
                stdout, stderr = current_proc.communicate(timeout=timeout)

                # it was put here for `lxc`, maybe, lxc has a bug,
                # to receive an exit code after `wait()`, we need to wait extra time (~3 sec),
                # otherwise a related process is still running,
                # and this case was caught on a bare metal server that may work slower
                # TODO it is not good place for it, and
                # TODO it is not a good workaround at all, need to create something else in the future
                if ("lxc " in cmd) and ("stop" in cmd):
                    self.LOGGER.warning(
                        "Possibly, a command to stop LXC is in the progress, wait extra {0} sec.".format(timeout),
                    )
                    time.sleep(timeout)

            except subprocess.TimeoutExpired as to_exc:
                current_proc.kill()
                stdout, stderr = current_proc.communicate()
                raise error.ProcessKilledException() from to_exc

            except Exception as exc:
                err_msg = "Error running command `{0}`".format(cmd)
                self.LOGGER.exception(err_msg)
                raise error.CommandExecutionException(err_msg) from exc

        if current_proc.returncode != 0:
            raise error.ProcessBadExitStatusException(
                '\nprocess: {0};\nstderr: {1}'.format(current_proc, stderr),
            )

        self.LOGGER.debug("stdout: {0}".format(stdout))
        if stderr:
            # success exit code does NOT always tell us that app finished correctly,
            # as a good example is running a command `timeout 5 <command>`, if <command> does not exist
            # `timeout` returns 0(zero exit code) with an error message, so, it hides an error
            self.LOGGER.error("stderr: {0}".format(stderr))
            raise error.CommandExecutionException(
                "Error happened despite a success exit code: {0}".format(stderr),
            )

        return stdout, stderr

    def mkdir(self, path: str):
        """
        Create directory on a node.

        Args:
            path (str): path to directory to create
        """
        os.makedirs(path, exist_ok=True)

    def copy_file(self, filename: str, content: Any):
        """
        Copy file.

        Args:
            filename (str): filename to copy
            content (Any): content to copy
        """
        # workdir will be ignored if an absolute filename is passed
        filename = os.path.join(self.workdir, filename)
        dirname = os.path.dirname(filename)

        # assume that workdir exists to avoid unnecessary actions
        if dirname != self.workdir:
            self.mkdir(dirname)

        with open(filename, "wt") as f:
            f.write(content)

    def remove_file(self, filename: str):
        """
        Remove file.

        Args:
            filename (str): filename to remove
        """
        if self.DEBUG_FILES:
            self.LOGGER.warning("Removing {0}: cancelled because of DEBUG_FILES is True".format(filename))
        else:
            try:
                os.remove(filename)
            except FileNotFoundError:
                self.LOGGER.warning("Removing {0}: file not found".format(filename))

    def wait_available(self) -> bool:
        """
        Wait for a node.

        Returns:
            (bool): True, if ready
        """
        return True

    def get_max_thread_count(self) -> int:
        """
        Get number of max threads on a node.

        Returns:
            (int) number of max threads
        """
        out, _ = self.run_cmd("grep -c processor /proc/cpuinfo")
        math_obj = re.match(r"^(\d+)$", out.decode())

        if not math_obj:
            return 1

        return int(math_obj.group(1))


class RemoteNode(INode):
    """Remote node class."""
    
    def __init__(self, ntype: str, hostname: str, workdir: str, user: str, port: int = 22):
        """
       Init class instance.

       Args:
           ntype (str): node type
           hostname (str): node hostname
           workdir (str): node workdir
           user (str): username to work with a node
           port (str): port to connect to a remote node
       """
        super().__init__(ntype=ntype, hostname=hostname, workdir=workdir)
        self.user = user
        self.port = port
        self._ssh: Optional[paramiko.SSHClient] = None
        self._connect()

    def _connect(self):
        """Open SSH connection to node if remote. Returns False on SSH errors."""
        try:
            self._ssh = paramiko.SSHClient()
            self._ssh.load_system_host_keys()
            # Workaround: paramiko prefer RSA keys to ECDSA, so add RSA
            # key to known_hosts.
            self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self._ssh.connect(
                hostname=self.host, username=self.user, port=self.port, timeout=DEFAULT_TIMEOUT,
            )
        except Exception as conn_exc:
            self.LOGGER.exception("Error connecting to {0} by SSH: {1}".format(self.host, conn_exc))

    def run_cmd(self, cmd: str, timeout: int = DEFAULT_TIMEOUT, env: Optional[dict] = None) -> tuple[bytes, bytes]:
        """
        Run command.

        Args:
            cmd (str): command to run
            timeout (int): command running timeout
            env (Optional[dict]): environment variables to execute command with

        Returns:
            (tuple[bytes, bytes]): stdout, stderr

        Raises:
            error.ProcessBadExitStatusException: if an exit code is not 0(zero)
            error.CommandExecutionException: if something happened during the execution
        """
        self.LOGGER.info("Run command '{0}' on host {1} with environment {2}".format(cmd, self.host, env))

        # we could simply pass environment to exec_command(), but openssh' default
        # is to reject such environment variables, so pass them via env(1)
        if env:
            cmd = " ".join(
                [
                    "env",
                    " ".join(["{0}='{1}'".format(k, v) for k, v in env.items()]),
                    cmd,
                ],
            )
            self.LOGGER.debug("Effective command '{0}' after injecting environment".format(cmd))

        try:
            # TODO #120: the same as for LocalNode - provide an interface to check
            # whether the command is executed and when it's terminated and/or
            # kill it when necessary.
            _, out_f, err_f = self._ssh.exec_command(cmd, timeout=timeout)
            stdout = out_f.read()
            stderr = err_f.read()

        except Exception as exc:
            err_msg = "Error running command `{0}` on {1}".format(cmd, self.host),
            self.LOGGER.exception(err_msg)
            raise error.CommandExecutionException(err_msg) from exc

        if out_f.channel.recv_exit_status() != 0:
            raise error.ProcessBadExitStatusException(
                '\nCurrent exit status is `{0}`\nstderr: {1}'.format(out_f.channel.recv_exit_status(), stderr),
            )

        self.LOGGER.debug("stdout: {0}".format(stdout))
        if stderr:
            # success exit code does NOT always tell us that app finished correctly,
            # as a good example is running a command `timeout 5 <command>`, if <command> does not exist
            # `timeout` returns 0(zero exit code) with an error message, so, it hides an error
            self.LOGGER.error("stderr: {0}".format(stderr))
            raise error.CommandExecutionException(
                "Error happened despite a success exit code: {0}".format(stderr),
            )

        return stdout, stderr

    def mkdir(self, path: str):
        """
        Create directory on a node.

        Args:
            path (str): path to directory to create
        """
        self.run_cmd("mkdir -p {0}".format(path))

    def copy_file(self, filename: str, content: Any):
        """
        Copy file.

        Args:
            filename (str): filename to copy
            content (Any): content to copy
        """
        # workdir will be ignored if an absolute filename is passed
        filename = os.path.join(self.workdir, filename)
        dirname = os.path.dirname(filename)

        # assume that workdir exists to avoid unnecessary actions
        if dirname != self.workdir:
            self.mkdir(dirname)

        try:
            sftp = self._ssh.open_sftp()
            sfile = sftp.file(filename, "wt", -1)
            sfile.write(content)
            sfile.flush()
            sftp.close()
        except Exception as copy_exc:
            self.LOGGER.exception(
                "Error copying file {0} to {1}: {2}".format(filename, self.host, copy_exc),
            )

    def remove_file(self, filename: str):
        """
        Remove file.

        Args:
            filename (str): filename to remove
        """
        if DEBUG_FILES:
            self.LOGGER.warning("Removing {0}: cancelled because of DEBUG_FILES is True".format(filename))

        else:
            sftp = self._ssh.open_sftp()
            try:
                sftp.unlink(filename)
            except IOError as e:
                if e.errno != errno.ENOENT:
                    self.LOGGER.warning("Removing {0}: file not found".format(filename))

            sftp.close()

    def wait_available(self) -> bool:
        """
        Wait for a node.

        Returns:
            (bool): True, if ready
        """
        self.LOGGER.debug("Waiting for {0} node, host {1}".format(self.type, self.host))
        timeout = float(tf_cfg.cfg.get(self.type, "unavailable_timeout"))
        t0 = time.time()

        while True:
            t = time.time()
            dt = t - t0

            if dt > timeout:
                self.LOGGER.error("Node {0} is not available, host {1}".format(self.type, self.host))
                return False

            res, _ = self.run_cmd("echo -n check", timeout=1)

            if res.decode() == "check":
                self.LOGGER.debug("Node {0} is available, host {1}".format(self.type, self.host))
                return True

            time.sleep(1)

    def get_max_thread_count(self) -> int:
        """
        Get number of max threads on a node.

        Returns:
            (int) number of max threads
        """
        out, _ = self.run_cmd("grep -c processor /proc/cpuinfo")
        math_obj = re.match(r"^(\d+)$", out.decode())

        if not math_obj:
            return 1

        return int(math_obj.group(1))


def create_node(host):
    hostname = tf_cfg.cfg.get(host, "hostname")
    workdir = tf_cfg.cfg.get(host, "workdir")

    if hostname != "localhost":
        port = int(tf_cfg.cfg.get(host, "port"))
        username = tf_cfg.cfg.get(host, "user")
        return RemoteNode(host, hostname, workdir, username, port)
    return LocalNode(host, hostname, workdir)


# -------------------------------------------------------------------------------
# Global accessible SSH/Local connections
# -------------------------------------------------------------------------------

client: Optional[INode] = None
tempesta: Optional[INode] = None
server: Optional[INode] = None
host: Optional[INode] = None


def connect():
    global client
    client = create_node("Client")

    global tempesta
    tempesta = create_node("Tempesta")

    global server
    server = create_node("Server")

    global host
    host_workdir = tf_cfg.cfg.get("General", "workdir")
    host = LocalNode("General", "localhost", host_workdir)

    for node in [client, server, tempesta, host]:
        node.mkdir(node.workdir)


def wait_available():
    global client
    global server
    global tempesta

    for node in [client, server, tempesta]:
        if not node.wait_available():
            return False
    return True


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
