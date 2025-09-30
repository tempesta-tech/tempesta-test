"""lxc backend server."""

import json
from dataclasses import dataclass

from framework import stateful
from helpers import error, port_checks, remote, tempesta, tf_cfg, util
from helpers.util import fill_template

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

website_port = tf_cfg.cfg.get("Server", "website_port")


@dataclass
class LXCServerArguments:
    """
    Interface class for LXC container server.
    Contains all accepted arguments (fields) supported by `LXCServer`.
    Args:
      id: backend server ID
      container_name: argument to lxc start/stop
      container_ip: IP address of the server (set from config)
      conns_n: number of TCP connection to TempestaFW
    """

    id: str
    container_name: str = tf_cfg.cfg.get("Server", "lxc_container_name")
    container_ip: str = tf_cfg.cfg.get("Server", "ip")
    conns_n: int = tempesta.server_conns_default()
    healthcheck_timeout: int = 10

    @classmethod
    def get_arg_names(cls) -> list[str]:
        """Returns list of `LXCServer` supported argument names."""
        return list(cls.__dataclass_fields__.keys())


class LXCServer(LXCServerArguments, stateful.Stateful, port_checks.FreePortsChecker):
    def __init__(self, **kwargs):
        # Initialize using the `LXCServerArguments` interface,
        # with only supported arguments
        super().__init__(**{k: kwargs[k] for k in self.get_arg_names() if k in kwargs})
        stateful.Stateful.__init__(self, id_=kwargs["id"])
        self.node = remote.server

    def clear_stats(self) -> None:
        super().clear_stats()

    @staticmethod
    def _construct_cmd(args: list[str]) -> str:
        c = " ".join(["lxc", *args])
        return c

    def run_start(self):
        """
        In the framework, lxc server uses only for tempesta-tech website.
        So container must be started manually before running the tests
        and shutdown after the tests.
        """

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

    def __check_connection(self):
        """Wait for the both checks to be False."""
        try:
            # apache2 in the lxc container works on 80 and 443 ports, but we use only 80 port
            self._construct_cmd([f"exec {self.container_name} -- sh -c 'ss -tlnp | grep '80''"])
            first_check = False
        except error.BaseCmdException:
            first_check = True

        second_check = (
            self.number_of_tcp_connections(self.container_ip, website_port) < self.conns_n
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


def lxc_srv_factory(server, name, tester):
    def fill_args(name):
        server[name] = {k: fill_template(v, server) for k, v in (server.get(name) or {}).items()}

    # Apply `fill_template` to arguments of dict type
    fill_args("env")

    return LXCServer(**server)
