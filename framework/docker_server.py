"""Docker containers backend server."""
import tarfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

import framework.port_checks as port_checks
from framework.tester import register_backend
from helpers import remote, stateful, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"


@dataclass
class DockerServerArguments:
    """Interface class for Docker container server.
    Contains all accepted arguments (fields) supported by `DockerServer`.
    """

    id: str
    tag: str
    server_ip: str
    general_workdir: str
    server_workdir: str
    build_timeout: int = 300
    stop_timeout: int = 6
    ports: Dict[int, int] = field(default_factory=dict)
    check_ports: List[Dict[str, str]] = field(default_factory=list)
    cmd_args: str = ""
    entrypoint: str = None

    @classmethod
    def get_kwargs(cls) -> List[str]:
        """Returns list of `DockerServer` supported argument names."""
        return list(cls.__dataclass_fields__.keys())


class DockerServer(DockerServerArguments, stateful.Stateful, port_checks.FreePortsChecker):
    """
    The set of wrappers to manage Docker container, such as to start,
    stop, get statistics etc., from other Python classes.

    Args:
      id: backend server ID
      tag: image to use from the `docker` directory
      server_ip: IP address of the server
      general_workdir: Path to temporary files
      server_workdir: Path to temporary files on the server node
      build_timeout: container build operation timeout
      stop_timeout: container stop operation timeout
      ports: host-container map of published ports
      check_ports: list of IP+port to check for availability before container is started
      cmd_args: additional `docker run` command arguments
      entrypoint: overwrite the default ENTRYPOINT of the image
    """

    def __init__(self, **kwargs):
        # Initialize using the `DockerServerArguments` interface,
        # with only supported arguments
        super().__init__(**{k: kwargs[k] for k in self.get_kwargs() if k in kwargs})
        self.node = remote.server
        self.container_id = None
        self.stop_procedures = [self.stop_server, self.cleanup]

    @property
    def image_name(self):
        """Docker image name."""
        return f"tt-{self.tag}"

    @property
    def context_path(self):
        """Path to the build context directory - directory that contains
        the files and directories that will be available to the Docker engine
        during the image build stage.
        """
        return Path("docker") / f"{self.tag}"

    @property
    def local_tar_path(self):
        """Path to store the build context archive locally."""
        return Path(self.general_workdir) / f"{self.image_name}.tar.gz"

    @property
    def remote_tar_path(self):
        """Path to store the build context archive on the server."""
        return Path(self.server_workdir) / f"{self.image_name}.tar.gz"

    def run_start(self):
        tf_cfg.dbg(3, f"\tDocker Server: Start {self.id} ({self.tag})")
        self.check_ports_status()
        self._build_image()
        stdout, stderr = self.node.run_cmd(
            self._form_run_command(), err_msg=self._form_error(action="start")
        )
        tf_cfg.dbg(3, stdout, stderr)
        if stderr or not stdout:
            error.bug(self._form_error(action="run"))
        self.container_id = stdout.decode()

    def wait_for_connections(self, timeout=5):
        if self.state != stateful.STATE_STARTED:
            return False

        t0 = time.time()
        t = time.time()
        while t - t0 <= timeout:
            if self.check_ports_established(ip=self.server_ip, ports=self.ports.keys()):
                return True
            time.sleep(0.001)  # to prevent redundant CPU usage
            t = time.time()

        return False

    def stop_server(self):
        tf_cfg.dbg(3, f"\tDocker server: Stop {self.id} ({self.tag})")
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
        cmd = f"cat {self.remote_tar_path} | docker build - --tag {self.image_name}"
        tf_cfg.dbg(3, f"Docker command formatted: {cmd}")
        return cmd

    def _form_run_command(self):
        ports = " ".join(f"-p {host}:{container}" for host, container in self.ports.items())
        entrypoint = f"--entrypoint {self.entrypoint}" if self.entrypoint else ""
        cmd = f"docker run -d --rm {ports} {entrypoint} {self.image_name} {self.cmd_args}"
        tf_cfg.dbg(3, f"Docker command formatted: {cmd}")
        return cmd

    def _form_stop_command(self):
        # `docker stop` `--time` is "Seconds to wait for stop before killing it".
        # Uses a value one second less than the total allowed time for the operation.
        timeout = max(self.stop_timeout - 1, 1)
        cmd = f"docker stop --time {timeout} {self.container_id}"
        tf_cfg.dbg(3, f"Docker command formatted: {cmd}")
        return cmd

    def _form_error(self, action):
        return f"Can't {action} Docker server"


def docker_srv_factory(server, name, tester):
    return DockerServer(**server)


register_backend("docker", docker_srv_factory)
