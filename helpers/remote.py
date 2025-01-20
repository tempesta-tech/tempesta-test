"""
Module to work with nodes: local and remote(via SSH).

The API is required to transparently handle both cases - Tempesta and the framework
on the same node (developer test case), or on separate machines (CI case).
"""

import abc
import errno
import logging
import os
import re
import shutil
import subprocess
import time
from typing import Optional, Union

import paramiko

import run_config
from helpers import error, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

# Don't remove files from remote node. Helpful for tests development.
# The flag is also managed from many places, for example `run_tests.py` and `./t_stress/test_stress.py`
# this is the reason it declared outside any node class and linked inside them.
# TODO may be a good candidate to declare it where all constants are declared (in the future).
DEBUG_FILES = False

# Default timeout for SSH sessions and command processing.
# TODO may be a good candidate to declare it where all constants are declared (in the future).
DEFAULT_TIMEOUT = 10

logger = tf_cfg.LOGGER


class ANode(object, metaclass=abc.ABCMeta):
    """Node abstract class."""

    _logger: logging.Logger = logger

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
        self._numa_nodes_n: int = 0
        self._max_threads_n: int = 0

    def _numa_nodes_count(self) -> int:
        """
        Executes shell command on the node to get number of NUMA nodes

        Returns:
            (int) number of NUMA nodes
        """
        cmd = f"lscpu | grep -oP 'NUMA node\(s\):\s*\K\d+'"
        out = self.run_cmd(cmd)
        return int(out[0].decode().strip("\n"))

    def _threads_count(self) -> int:
        """
        Executes shell command on the node to get number of CPU threads

        Returns:
            (int) number of CPU threads
        """
        out, _ = self.run_cmd("grep -c processor /proc/cpuinfo")
        math_obj = re.match(r"^(\d+)$", out.decode())

        if not math_obj:
            return 1

        return int(math_obj.group(1))

    @abc.abstractmethod
    def run_cmd(
        self,
        cmd: str,
        timeout: Union[int, float, None] = DEFAULT_TIMEOUT,
        env: Optional[dict] = None,
        is_blocking: bool = True,
    ) -> (bytes, bytes):
        """
        Run command.

        Args:
            cmd (str): command to run
            timeout (Union[int, float, None]): command running timeout
            env (Optional[dict]): environment variables to execute command with
            is_blocking (bool): if True, run a command and wait for it, otherwise just start it (no read stdout, stderr)

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
    def copy_file(self, filename: str, content: str):
        """
        Copy file.

        Args:
            filename (str): filename to copy
            content (str): content to copy
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
    def copy_file_to_node(self, file: str, dest_dir: str):
        """
        Copy a file to a node.

        Args:
            (file) file name to copy
            (dest_dir): destination directory
        """

    def get_max_thread_count(self) -> int:
        """
        Get number of max threads on a node.

        Returns:
            (int) number of max threads
        """
        return self._max_threads_n

    def get_numa_nodes_count(self) -> int:
        """
        Get number of NUMA nodes on a node.

        Returns:
            (int) number of NUMA nodes
        """
        return self._numa_nodes_n

    def _post_init(self):
        """
        Finilize initialization of the Node.
        """
        self._numa_nodes_n = self._numa_nodes_count()
        self._max_threads_n = self._threads_count()


class LocalNode(ANode):
    """Local node class."""

    def run_cmd(
        self,
        cmd: str,
        timeout: Union[int, float, None] = DEFAULT_TIMEOUT,
        env: Optional[dict] = None,
        is_blocking: bool = True,
    ) -> tuple[bytes, bytes]:
        """
        Run command.

        Args:
            cmd (str): command to run
            timeout (Union[int, float, None]): command running timeout
            env (Optional[dict]): environment variables to execute command with
            is_blocking (bool): if True, run a command and wait for it, otherwise just start it (no read stdout, stderr)

        Returns:
            (tuple[bytes, bytes]): stdout, stderr

        Raises:
            error.ProcessBadExitStatusException: if an exit code is not 0(zero)
            error.CommandExecutionException: if something happened during the execution
            error.ProcessKilledException: if a process was killed
        """
        msg_is_blocking = "" if is_blocking else "***NON-BLOCKING (no wait to finish)*** "
        self._logger.debug(f"An initial command before changes: '{cmd}'")

        # Popen() expects full environment
        env_full = os.environ.copy()
        if env:
            env_full.update(env)
        if run_config.SAVE_SECRETS and "curl" in cmd:
            env_full["SSLKEYLOGFILE"] = "./secrets.txt"

        self._logger.debug(f"All environment variables after updating: {env_full}")
        self._logger.info(
            f"Run command '{cmd}' {msg_is_blocking}on host {self.host} with environment {env}"
        )

        if is_blocking:
            std_arg = subprocess.PIPE
        else:
            std_arg = None

        with subprocess.Popen(
            cmd, shell=True, stdout=std_arg, stderr=std_arg, env=env_full
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

            except subprocess.TimeoutExpired as to_exc:
                current_proc.kill()
                stdout, stderr = current_proc.communicate()
                raise error.ProcessKilledException() from to_exc

            except Exception as exc:
                err_msg = f"Error running command `{cmd}`"
                self._logger.exception(err_msg)
                raise error.CommandExecutionException(err_msg) from exc

        if current_proc.returncode != 0:
            raise error.ProcessBadExitStatusException(
                f"\nprocess: {current_proc};\nstderr: {stderr}",
                stdout=stdout,
                stderr=stderr,
                rt=current_proc.returncode,
            )

        if stdout:
            self._logger.debug(f"stdout: {stdout}")
        if stderr:
            self._logger.error(f"stderr: {stderr}")

        return stdout, stderr

    def mkdir(self, path: str):
        """
        Create directory on a node.

        Args:
            path (str): path to directory to create
        """
        self._logger.debug(f"Making directory `{path}`.")
        os.makedirs(path, exist_ok=True)

    def copy_file(self, filename: str, content: str):
        """
        Copy file.

        Args:
            filename (str): filename to copy
            content (str): content to copy
        """
        # workdir will be ignored if an absolute filename is passed
        filename = os.path.join(self.workdir, filename)
        dirname = os.path.dirname(filename)

        self._logger.debug(f"Copying file `{filename}`.")

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
        if DEBUG_FILES:
            self._logger.warning(f"Removing `{filename}`: cancelled because of debug files is True")

        else:
            self._logger.debug(f"Removing `{filename}`.")
            try:
                os.remove(filename)
            except FileNotFoundError:
                self._logger.warning(f"Removing `{filename}`: file not found")

    def wait_available(self) -> bool:
        """
        Wait for a node.

        Returns:
            (bool): True, if ready
        """
        return True

    def copy_file_to_node(self, file: str, dest_dir: str):
        """
        Copy a file to a node.

        Args:
            (file) file name to copy
            (dest_dir): destination directory
        """
        self._logger.debug(f"Copying `{file}` to a node with destination `{dest_dir}`")
        shutil.copy(file, dest_dir)


class RemoteNode(ANode):
    """Remote node class."""

    def __init__(
        self,
        ntype: str,
        hostname: str,
        workdir: str,
        user: str,
        port: int = 22,
        ssh_key: Optional[str] = None,
    ):
        """
        Init class instance.

        Args:
            ntype (str): node type
            hostname (str): node hostname
            workdir (str): node workdir
            user (str): username to work with a node
            ssh_key (str): ssh key location
            port (str): port to connect to a remote node
        """
        super().__init__(ntype=ntype, hostname=hostname, workdir=workdir)
        self.user = user
        self.port = port
        self._ssh_key: Optional[str] = ssh_key
        self._ssh: Optional[paramiko.SSHClient] = None
        self._connect()

    def _connect(self):
        """
        Open SSH connection to a node.

        if SSH key (self,_ssh_key) was provided - connection by the key (self.__connect_with_explicit_keys),
        otherwise by loading system keys (self.__connect_by_loading_keys_from_system)
        """
        self._ssh = paramiko.SSHClient()
        # Workaround: paramiko prefer RSA keys to ECDSA, so add RSA
        # key to known_hosts.
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if self._ssh_key:
            self.__connect_with_explicit_keys()

        else:
            self.__connect_by_loading_keys_from_system()

    def __connect_by_loading_keys_from_system(self):
        """Open SSH connection to a node by loading host keys from a system."""
        self._logger.info(
            f"Trying to connect by SSH to {self.host}:{self.port} by load host keys from a system."
        )

        try:
            self._ssh.load_system_host_keys()
            self._ssh.connect(
                hostname=self.host,
                username=self.user,
                port=self.port,
                timeout=DEFAULT_TIMEOUT,
            )
        except Exception as conn_exc:
            self._logger.exception(f"Error connecting to {self.host} by SSH: {conn_exc}")
            raise conn_exc

    def __connect_with_explicit_keys(self):
        """
        Open SSH connection to a node with provided keys.

        Before invoking the method, it is better to check for existence of a `self._ssh_key` attr.
        """
        self._logger.info(
            f"Trying to connect by SSH to {self.host}:{self.port} using key {self._ssh_key}."
        )

        try:
            self._ssh.connect(
                hostname=self.host,
                port=self.port,
                username=self.user,
                key_filename=self._ssh_key,
                timeout=DEFAULT_TIMEOUT,
            )
        except Exception as conn_exc:
            self._logger.exception(f"Error connecting to {self.host} by SSH: {conn_exc}")
            raise conn_exc

    def run_cmd(
        self,
        cmd: str,
        timeout: Union[int, float, None] = DEFAULT_TIMEOUT,
        env: Optional[dict] = None,
        is_blocking: bool = True,
    ) -> tuple[bytes, bytes]:
        """
        Run command.

        Args:
            cmd (str): command to run
            timeout (Union[int, float, None]): command running timeout
            env (Optional[dict]): environment variables to execute command with
            is_blocking (bool): if True, run a command and wait for it, otherwise just start it (no read stdout, stderr)
                no effect for the method, all calls are blocking

        Returns:
            (tuple[bytes, bytes]): stdout, stderr

        Raises:
            error.ProcessBadExitStatusException: if an exit code is not 0(zero)
            error.CommandExecutionException: if something happened during the execution
        """
        self._logger.debug(f"An initial command before changes: '{cmd}'")

        # we could simply pass environment to exec_command(), but openssh' default
        # is to reject such environment variables, so pass them via env(1)
        if env:
            cmd = " ".join(
                [
                    "env",
                    " ".join([f"{env_k}='{env_v}'" for env_k, env_v in env.items()]),
                    cmd,
                ],
            )
            self._logger.debug(f"Effective command `{cmd}` after injecting environment")

        self._logger.info(f"Run command '{cmd}' on host {self.host} with environment {env}")

        try:
            # TODO #120: the same as for LocalNode - provide an interface to check
            # whether the command is executed and when it's terminated and/or
            # kill it when necessary.
            _, out_f, err_f = self._ssh.exec_command(cmd, timeout=timeout)
            stdout = out_f.read()
            stderr = err_f.read()

        except Exception as exc:
            err_msg = (f"Error running command `{cmd}` on {self.host}",)
            self._logger.exception(err_msg)
            raise error.CommandExecutionException(err_msg) from exc

        if out_f.channel.recv_exit_status() != 0:
            raise error.ProcessBadExitStatusException(
                f"\nCurrent exit status is `{out_f.channel.recv_exit_status()}`\nstderr: {stderr}",
                stdout=stdout,
                stderr=stderr,
                rt=out_f.channel.recv_exit_status(),
            )

        if stdout:
            self._logger.debug(f"stdout: {stdout}")
        if stderr:
            self._logger.error(f"stderr: {stderr}")

        return stdout, stderr

    def mkdir(self, path: str):
        """
        Create directory on a node.

        Args:
            path (str): path to directory to create
        """
        self._logger.debug(f"Making directory `{path}`.")
        self.run_cmd(f"mkdir -p {path}")

    def copy_file(self, filename: str, content: str):
        """
        Copy file.

        Args:
            filename (str): filename to copy
            content (str): content to copy
        """
        # workdir will be ignored if an absolute filename is passed
        filename = os.path.join(self.workdir, filename)
        dirname = os.path.dirname(filename)

        self._logger.debug(f"Copying file by sftp `{filename}`.")

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
            self._logger.exception(
                f"Error copying file `{filename}` to {self.host}: {copy_exc}",
            )

    def remove_file(self, filename: str):
        """
        Remove file.

        Args:
            filename (str): filename to remove
        """
        if DEBUG_FILES:
            self._logger.warning(f"Removing `{filename}`: cancelled because of debug files is True")

        else:
            self._logger.debug(f"Removing `{filename}`.")

            sftp = self._ssh.open_sftp()
            try:
                sftp.unlink(filename)
            except IOError as e:
                if e.errno != errno.ENOENT:
                    self._logger.warning(f"Removing `{filename}`: file not found")

            sftp.close()

    def wait_available(self) -> bool:
        """
        Wait for a node.

        Returns:
            (bool): True, if ready
        """
        self._logger.debug(f"Waiting for {self.type} node, host {self.host}")
        timeout = float(tf_cfg.cfg.get(self.type, "unavailable_timeout"))
        t0 = time.time()

        while True:
            t = time.time()
            dt = t - t0

            if dt > timeout:
                self._logger.error(f"Node {self.type} is not available, host {self.host}")
                return False

            res, _ = self.run_cmd("echo -n check", timeout=1)

            if res.decode() == "check":
                self._logger.debug(f"Node {self.type} is available, host {self.host}")
                return True

            time.sleep(1)

    def copy_file_to_node(self, file: str, dest_dir: str):
        """
        Copy a file to a node.

        Args:
            (file) file name to copy
            (dest_dir): destination directory
        """
        self._logger.debug(f"Copying `{file}` to a node with destination `{dest_dir}`")
        try:
            sftp = self._ssh.open_sftp()

            self._change_perm(target=dest_dir)

            sftp.put(file, dest_dir)
            sftp.close()
        except Exception:
            self._logger.exception(f"Error copying file {file} to {self.host}")


def create_node(host_type: str):
    hostname = tf_cfg.cfg.get(host_type, "hostname")
    workdir = tf_cfg.cfg.get(host_type, "workdir")

    if hostname != "localhost":
        node = RemoteNode(
            ntype=host_type,
            hostname=hostname,
            workdir=workdir,
            user=tf_cfg.cfg.get(host_type, "user"),
            port=int(tf_cfg.cfg.get(host_type, "port")),
            ssh_key=tf_cfg.cfg.get(host_type, "ssh_key"),
        )

        node._post_init()
        return node
    node = LocalNode(ntype=host_type, hostname=hostname, workdir=workdir)
    node._post_init()
    return node


# -------------------------------------------------------------------------------
# Global accessible SSH/Local connections
# -------------------------------------------------------------------------------

client: Optional[ANode] = None
tempesta: Optional[ANode] = None
server: Optional[ANode] = None
host: Optional[ANode] = None


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
