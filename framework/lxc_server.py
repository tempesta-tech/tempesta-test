"""lxc backend server."""

import json
import subprocess
import time
from dataclasses import dataclass, field
from typing import List, Dict

from framework import port_checks
from framework.templates import fill_template
from helpers import error, remote, stateful, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

LXC_PROXY_PREFIX = "tempesta-test"


@dataclass
class LXCServerArguments:
    """Interface class for LXC container server.
    Contains all accepted arguments (fields) supported by `LXCServer`.
    """

    id: str
    container_name: str
    server_ip: str
    healthcheck_command: str
    healthcheck_timeout: int = 10
    ports: Dict[int, int] = field(default_factory=dict)

    @classmethod
    def get_arg_names(cls) -> List[str]:
        """Returns list of `LXCServer` supported argument names."""
        return list(cls.__dataclass_fields__.keys())


class LXCServer(LXCServerArguments, stateful.Stateful, port_checks.FreePortsChecker):
    """
    Args:
      id: backend server ID
      container_name: argument to lxc start/stop
      server_ip: IP address of the server (set from config)
      healthcheck_command: executed inside the container, should return exit code 0 when container is ready
      healthcheck_timeout: how many seconds to wait for a container to start before giving up
      ports: dict of external/internal ports to proxy to/from container
    """

    def __init__(self, **kwargs):
        # Initialize using the `LXCServerArguments` interface,
        # with only supported arguments
        super().__init__(**{k: kwargs[k] for k in self.get_arg_names() if k in kwargs})
        self.node = remote.server
        self.host = remote.host
        self.stop_procedures = [self.stop_server]

    def _construct_cmd(self, args: list[str]) -> list[str]:
        c = ["lxc", *args]
        tf_cfg.dbg(3, f"\tlxc cmd: {c}")
        return c

    def run_start(self):
        tf_cfg.dbg(3, f"\tlxc server: start {self.id}")
        p = subprocess.run(
            args=self._construct_cmd(["start", self.container_name]),
        )
        if p.returncode != 0:
            error.bug("unable to start lxc container server.")
        self._proxy_setup()
        t0 = time.time()
        while time.time() - t0 < self.healthcheck_timeout:
            p = subprocess.run(
                args=self._construct_cmd(
                    ["exec", self.container_name, "--", "bash", "-c", self.healthcheck_command]
                ),
                timeout=self.healthcheck_timeout,
            )
            if p.returncode == 0:
                return False
            time.sleep(1)
        error.bug("lxc container is unhealthy.")

    @property
    def status(self):
        """Status of the container: 'starting', 'running', 'stopped'."""
        p = subprocess.run(self._construct_cmd(["list", "-f", "json"]), capture_output=True)
        if p.stderr or not p.stdout:
            error.bug("error running lxc list", p.stdout, p.stderr)
        status: str | None = None
        try:
            lxc_list = json.loads(p.stdout)
            for c in lxc_list:
                if c["name"] == self.container_name:
                    status = c["status"].lower()
        except json.JSONDecodeError:
            error.bug("unable to parse output of lxc list")
        return status

    def _proxy_setup(self):
        for ext_port, int_port in self.ports.items():
            proxy_name = f"{LXC_PROXY_PREFIX}-{ext_port}-{int_port}"
            p = subprocess.run(
                self._construct_cmd(
                    [
                        "config",
                        "device",
                        "add",
                        self.container_name,
                        proxy_name,
                        "proxy",
                        f"listen=tcp:{self.server_ip}:{ext_port}",
                        f"connect=tcp:127.0.0.1:{int_port}",
                    ]
                ),
                capture_output=True,
            )
            if p.stderr or not p.stdout:
                error.bug("error setting up lxc proxy", p.stdout, p.stderr)

    def _proxy_teardown(self):
        p = subprocess.run(
            self._construct_cmd(["config", "device", "list", self.container_name]),
            capture_output=True,
        )
        if p.stderr or not p.stdout:
            error.bug("error tearing down lxc proxy", p.stdout, p.stderr)
        for d in p.stdout.splitlines():
            device = d.decode()
            if device.startswith(LXC_PROXY_PREFIX):
                p = subprocess.run(
                    self._construct_cmd(
                        ["config", "device", "remove", self.container_name, device]
                    ),
                    capture_output=True,
                )
                if p.stderr or not p.stdout:
                    error.bug("error tearing down lxc proxy", p.stdout, p.stderr)

    def wait_for_connections(self, timeout=10):
        """
        Wait until the container becomes running
        and Tempesta establishes connections to the server ports.
        """
        if self.state != stateful.STATE_STARTED:
            return False

        t0 = time.time()
        while time.time() - t0 < timeout:
            if self.status == "running":
                if self.check_ports_established(ip=self.server_ip, ports=self.ports.keys()):
                    return True
            time.sleep(0.1)  # to prevent redundant CPU usage
        return False

    def stop_server(self):
        tf_cfg.dbg(3, f"\tlxc server: Stop {self.id}")
        self._proxy_teardown()
        p = subprocess.run(
            self._construct_cmd(["stop", self.container_name]),
        )
        if p.returncode != 0:
            error.bug("unable to stop lxc server")


def lxc_srv_factory(server, name, tester):
    def fill_args(name):
        server[name] = {k: fill_template(v, server) for k, v in (server.get(name) or {}).items()}

    # Apply `fill_template` to arguments of dict type
    fill_args("env")

    return LXCServer(**server)
