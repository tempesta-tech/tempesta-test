"""lxc backend server."""

import json
from dataclasses import dataclass

from framework import port_checks
from framework.templates import fill_template
from helpers import error, remote, stateful, tempesta, tf_cfg, util

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

LXC_PREFIX = "tempesta-test"


@dataclass
class LXCServerArguments:
    """
    Interface class for LXC container server.
    Contains all accepted arguments (fields) supported by `LXCServer`.
    Args:
      id: backend server ID
      external_port: external port of the container
      internal_port: a port inside a container
      container_name: argument to lxc start/stop
      container_ip: IP address of the server (set from config)
      conns_n: number of TCP connection to TempestaFW
      make_snapshot: when set to true, tests will make a snapshot, run, then restore container
                     to its previous state
    """

    id: str
    external_port: str
    internal_port: str = "80"
    container_name: str = tf_cfg.cfg.get("Server", "lxc_container_name")
    container_ip: str = tf_cfg.cfg.get("Server", "ip")
    conns_n: int = tempesta.server_conns_default()
    healthcheck_timeout: int = 10
    make_snapshot: bool = False

    @classmethod
    def get_arg_names(cls) -> list[str]:
        """Returns list of `LXCServer` supported argument names."""
        return list(cls.__dataclass_fields__.keys())


class LXCServer(LXCServerArguments, stateful.Stateful, port_checks.FreePortsChecker):
    def __init__(self, **kwargs):
        # Initialize using the `LXCServerArguments` interface,
        # with only supported arguments
        super().__init__(**{k: kwargs[k] for k in self.get_arg_names() if k in kwargs})
        stateful.Stateful.__init__(self)
        self.node = remote.server
        self.stop_procedures = [self._proxy_teardown, self._stop_container]
        self._proxy_name = f"{LXC_PREFIX}-{self.external_port}-{self.internal_port}"
        self.__is_proxy_created = False

    @staticmethod
    def _construct_cmd(args: list[str]) -> str:
        c = " ".join(["lxc", *args])
        tf_cfg.dbg(3, f"\tlxc cmd: {c}")
        return c

    def run_start(self):
        tf_cfg.dbg(3, f"\tlxc server: start {self.id}")
        if self.make_snapshot:
            self._make_pretest_snapshot()
        self.node.run_cmd(self._construct_cmd(["start", self.container_name]))
        self._proxy_setup()

    @property
    def status(self):
        """Status of the container: 'starting', 'running', 'stopped'."""
        stdout, stderr = self.node.run_cmd(self._construct_cmd(["list", "-f", "json"]))
        status: str | None = None
        try:
            lxc_list = json.loads(stdout)
            for c in lxc_list:
                if c["name"] == self.container_name:
                    status = c["status"].lower()
        except json.JSONDecodeError:
            error.bug("unable to parse output of lxc list")
        return status

    def _make_pretest_snapshot(self):
        self.node.run_cmd(
            self._construct_cmd(["snapshot", self.container_name, LXC_PREFIX, "--reuse"]),
            timeout=20,
        )

    def _restore_pretest_snapshot(self):
        self.node.run_cmd(self._construct_cmd(["restore", self.container_name, LXC_PREFIX]))

    def _proxy_setup(self):
        """Create a connection between the internal port and the external port."""
        self.node.run_cmd(
            self._construct_cmd(
                [
                    "config",
                    "device",
                    "add",
                    self.container_name,
                    self._proxy_name,
                    "proxy",
                    f"listen=tcp:{self.container_ip}:{self.external_port}",
                    f"connect=tcp:127.0.0.1:{self.internal_port}",
                ]
            )
        )
        self.__is_proxy_created = True

    def _proxy_teardown(self):
        """The proxy should be removed if it was created before."""
        if self.__is_proxy_created:
            self.node.run_cmd(
                self._construct_cmd(
                    ["config", "device", "remove", self.container_name, self._proxy_name]
                )
            )
            self.__is_proxy_created = False

    def __check_connection(self):
        """Wait for the both checks to be False."""
        try:
            self.node.run_cmd(f"curl -If {self.container_ip}:{self.external_port}")
            first_check = False
        except remote.CmdError:
            first_check = True

        second_check = (
            self.number_of_tcp_connections(self.container_ip, self.external_port) < self.conns_n
        )
        return first_check or second_check

    def wait_for_connections(self, timeout=None):
        """
        Wait until the container becomes running
        and Tempesta establishes connections to the server ports.
        """
        if self.state != stateful.STATE_STARTED:
            return False

        return util.wait_until(
            wait_cond=self.__check_connection,
            timeout=timeout or self.healthcheck_timeout,
            poll_freq=0.1,
            abort_cond=lambda: self.status != "running",
        )

    def _stop_container(self):
        tf_cfg.dbg(3, f"\tlxc server: stop {self.id}")
        self.node.run_cmd(self._construct_cmd(["stop", self.container_name]))
        if self.make_snapshot:
            self._restore_pretest_snapshot()


def lxc_srv_factory(server, name, tester):
    def fill_args(name):
        server[name] = {k: fill_template(v, server) for k, v in (server.get(name) or {}).items()}

    # Apply `fill_template` to arguments of dict type
    fill_args("env")

    return LXCServer(**server)
