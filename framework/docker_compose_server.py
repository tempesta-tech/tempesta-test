"""Docker Compose backend server."""
import json
import subprocess
import time
from audioop import add
from dataclasses import dataclass, field
from os import path
from pathlib import Path
from subprocess import Popen
from typing import Dict, List

from framework import port_checks
from framework.templates import fill_template
from helpers import error, remote, stateful, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"


@dataclass
class DockerComposeServerArguments:
    """Interface class for Docker container server.
    Contains all accepted arguments (fields) supported by `DockerComposeServer`.
    """

    id: str
    project_name: str
    parent_compose_dir = Path("docker_compose")
    server_ip: str
    env: Dict[str, str] = field(default_factory=dict)
    ports: List[int] = field(default_factory=list)

    @classmethod
    def get_arg_names(cls) -> List[str]:
        """Returns list of `DockerServer` supported argument names."""
        return list(cls.__dataclass_fields__.keys())


class DockerComposeServer(
    DockerComposeServerArguments, stateful.Stateful, port_checks.FreePortsChecker
):
    """
    Args:
      id: backend server ID
      project_name: directory with docker-compose.yml
      check_ports: list of ports to check for availability before container is started
      env: environment (runtime) variables

      server_ip: IP address of the server (set from config)
      server_workdir: Path to temporary files on the server node (set from config)
      server_ip: IP address of the server (set from config)
    """

    def __init__(self, **kwargs):
        # Initialize using the `DockerServerArguments` interface,
        # with only supported arguments
        super().__init__(**{k: kwargs[k] for k in self.get_arg_names() if k in kwargs})
        self.node = remote.server
        self.host = remote.host
        self.stop_procedures = [self.stop_server]

    @property
    def local_workdir(self):
        return self.parent_compose_dir / self.project_name

    def _construct_cmd(self, action: str) -> list[str]:
        env_exports = ""
        if isinstance(self.node, remote.RemoteNode):
            self.env["DOCKER_HOST"] = f"ssh://{self.node.user}@{self.node.host}:{self.node.port}"
        for k, v in self.env.items():
            env_exports += f"export {k}={v};"
        return ["bash", "-c", f"cd {self.local_workdir}; {env_exports} docker compose {action}"]

    def run_start(self):
        tf_cfg.dbg(3, f"\tDocker Compose Server: Start {self.id} (dir {self.local_workdir})")
        p = subprocess.run(
            args=self._construct_cmd("up --detach"),
        )
        if p.returncode != 0:
            error.bug("unable to start docker compose server.")
        return False

    @property
    def health_status(self):
        """Status of the container: 'starting', 'healthy', 'unhealthy'."""
        p = subprocess.run(self._construct_cmd("ps --format=json"), capture_output=True)
        if p.stderr or not p.stdout:
            error.bug("error running docker compose ps", p.stdout, p.stderr)
        health = []
        try:
            for line in p.stdout.splitlines():
                ps: dict = json.loads(line.decode())
                health.append(ps.get("Health"))
        except json.JSONDecodeError:
            error.bug("unable to parse output of docker compose ps")

        status = "unhealthy" if "unhealthy" in health else "healthy"
        status = "starting" if "starting" in health else "healthy"
        return status

    def wait_for_connections(self, timeout=10):
        """
        Wait until the container becomes healthy
        and Tempesta establishes connections to the server ports.
        """
        if self.state != stateful.STATE_STARTED:
            return False

        t0 = time.time()
        t = time.time()
        while t - t0 <= timeout and self.health_status != "unhealthy":
            if self.health_status == "healthy":
                if self.check_ports_established(ip=self.server_ip, ports=self.ports):
                    return True
            time.sleep(0.1)  # to prevent redundant CPU usage
            t = time.time()
        return False

    def stop_server(self):
        tf_cfg.dbg(3, f"\tDocker Compose server: Stop {self.id} (dir {self.local_workdir})")
        p = subprocess.run(
            self._construct_cmd("down"),
        )
        if p.returncode != 0:
            error.bug("unable to stop docker compose server")


def docker_compose_srv_factory(server, name, tester):
    def fill_args(name):
        server[name] = {k: fill_template(v, server) for k, v in (server.get(name) or {}).items()}

    # Apply `fill_template` to arguments of dict type
    fill_args("env")

    return DockerComposeServer(**server)
