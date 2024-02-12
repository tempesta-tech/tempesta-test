"""Docker containers backend server."""
import json
import tarfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

import framework.port_checks as port_checks
from framework.templates import fill_template
from helpers import error, remote, stateful, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"


@dataclass
class DockerServerArguments:
    """Interface class for Docker container server.
    Contains all accepted arguments (fields) supported by `DockerServer`.
    """

    id: str
    image: str
    server_ip: str
    general_workdir: str
    server_workdir: str
    build_timeout: int = 300
    stop_timeout: int = 6
    ports: Dict[int, int] = field(default_factory=dict)
    check_ports: List[Dict[str, str]] = field(default_factory=list)
    build_args: Dict[str, str] = field(default_factory=dict)
    env: Dict[str, str] = field(default_factory=dict)
    entrypoint: str = None
    options: str = ""
    cmd_args: str = ""

    @classmethod
    def get_arg_names(cls) -> List[str]:
        """Returns list of `DockerServer` supported argument names."""
        return list(cls.__dataclass_fields__.keys())


class DockerServer(DockerServerArguments, stateful.Stateful):
    """
    The set of wrappers to manage Docker container, such as to start,
    stop, get statistics etc., from other Python classes.
    See `docker/README.md` and `selftests/test_docker_server.py` for usage examples.

    Args:
      id: backend server ID
      image: image to use from the `docker` directory
      server_ip: IP address of the server (set from config)
      general_workdir: Path to temporary files (set from config)
      server_workdir: Path to temporary files on the server node (set from config)
      build_timeout: container build operation timeout
      stop_timeout: container stop operation timeout
      ports: host-container map of published ports
      check_ports: list of IP+port to check for availability before container is started
      build_args: build-time variables
      env: environment (runtime) variables
      entrypoint: overwrite the default ENTRYPOINT of the image
      options: additional `docker run` command options
      cmd_args: additional `docker run` command arguments
    """

    def __init__(self, **kwargs):
        # Initialize using the `DockerServerArguments` interface,
        # with only supported arguments
        super().__init__(**{k: kwargs[k] for k in self.get_arg_names() if k in kwargs})
        self.node = remote.server
        self.container_id = None
        self.stop_procedures = [self.stop_server, self.cleanup]
        self.port_checker = port_checks.FreePortsChecker()

    @property
    def image_name(self):
        """
        Name used for the built image on the server:
        all test images are prefixed to distinguish from other images.
        """
        return f"tt-{self.image}"

    @property
    def context_path(self):
        """Path to the build context directory - directory that contains
        the files and directories that will be available to the Docker engine
        during the image build stage.
        """
        return Path("docker") / f"{self.image}"

    @property
    def local_tar_path(self):
        """Path to store the build context archive locally."""
        return Path(self.general_workdir) / f"{self.image_name}.tar.gz"

    @property
    def remote_tar_path(self):
        """Path to store the build context archive on the server."""
        return Path(self.server_workdir) / f"{self.image_name}.tar.gz"

    @property
    def health_status(self):
        """Status of the container: 'starting', 'healthy', 'unhealthy'."""
        stdout, stderr = self.node.run_cmd(
            self._form_inspect_health_command(), err_msg=self._form_error(action="inspect_health")
        )
        if stderr or not stdout:
            error.bug(self._form_error(action="inspect_health"))
        try:
            health = json.loads(stdout.decode())
        except json.JSONDecodeError:
            error.bug(self._form_error(action="decode_health"))
        status = health and health["Status"] or "unhealthy"
        if status == "unhealthy":
            tf_cfg.dbg(3, f"\tDocker Server: {self.id} is unhealthy: {stdout}")
        return status

    def run_start(self):
        tf_cfg.dbg(3, f"\tDocker Server: Start {self.id} (image {self.image})")
        self.port_checker.check_ports_status()
        self._build_image()
        stdout, stderr = self.node.run_cmd(
            self._form_run_command(), err_msg=self._form_error(action="start")
        )
        tf_cfg.dbg(3, stdout, stderr)
        if stderr or not stdout:
            error.bug(self._form_error(action="run"))
        self.container_id = stdout.decode().strip()

    def wait_for_connections(self, timeout=5):
        """
        Wait until the container becomes healthy
        and Tempesta establishes connections to the server ports.
        """
        if self.state != stateful.STATE_STARTED:
            return False

        t0 = time.time()
        t = time.time()
        while t - t0 <= timeout and self.health_status != "unhealthy":
            if self.health_status == "healthy" and self.port_checker.check_ports_established(
                ip=self.server_ip, ports=self.ports.keys()
            ):
                return True
            time.sleep(0.001)  # to prevent redundant CPU usage
            t = time.time()

        return False

    def stop_server(self):
        tf_cfg.dbg(3, f"\tDocker server: Stop {self.id} (image {self.image})")
        if self.container_id:
            self.node.run_cmd(
                self._form_stop_command(),
                timeout=self.stop_timeout,
                err_msg=self._form_error(action="stop"),
            )

    def cleanup(self):
        self.node.remove_file(str(self.remote_tar_path))
        self.local_tar_path.unlink(missing_ok=True)

    def _build_image(self):
        self._tar_context()
        self.node.copy_file_to_node(str(self.local_tar_path), str(self.remote_tar_path))
        stdout, stderr = self.node.run_cmd(
            self._form_build_command(),
            timeout=self.build_timeout,
            err_msg=self._form_error(action="build"),
        )
        tf_cfg.dbg(3, stdout, stderr)

    def _tar_context(self):
        """Archive the the build context directory."""
        with tarfile.open(self.local_tar_path, "w:gz") as tar:
            tar.add(self.context_path, arcname=".")

    def _form_build_command(self):
        build_args = " ".join(
            f"--build-arg {arg}='{value}'" for arg, value in self.build_args.items()
        )
        cmd = f"cat {self.remote_tar_path} | docker build - {build_args} --tag {self.image_name}"
        tf_cfg.dbg(3, f"Docker command formatted: {cmd}")
        return cmd

    def _form_run_command(self):
        ports = " ".join(f"-p {host}:{container}" for host, container in self.ports.items())
        env = " ".join(f"--env {arg}='{value}'" for arg, value in self.env.items())
        entrypoint = f"--entrypoint {self.entrypoint}" if self.entrypoint else ""
        cmd = (
            "docker run -d --rm"
            f" {ports} {env} {self.options} {entrypoint}"
            f" {self.image_name} {self.cmd_args}"
        )
        tf_cfg.dbg(3, f"Docker command formatted: {cmd}")
        return cmd

    def _form_stop_command(self):
        # `docker stop` `--time` is "Seconds to wait for stop before killing it".
        # Uses a value one second less than the total allowed time for the operation.
        timeout = max(self.stop_timeout - 1, 1)
        cmd = f"docker stop --time {timeout} {self.container_id}"
        tf_cfg.dbg(3, f"Docker command formatted: {cmd}")
        return cmd

    def _form_inspect_health_command(self):
        return f"docker inspect --format='{{{{json .State.Health}}}}' {self.container_id}"

    def _form_error(self, action):
        return f"Can't {action} Docker server"


def docker_srv_factory(server, name, tester):
    def fill_args(name):
        server[name] = {k: fill_template(v, server) for k, v in (server.get(name) or {}).items()}

    # Apply `fill_template` to arguments of dict type
    fill_args("build_args")
    fill_args("env")

    return DockerServer(**server)
