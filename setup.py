#!/usr/bin/env python3

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import abc
import argparse
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from helpers.tf_cfg import cfg

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"


# add to .gitignore
HOME_DIR = Path.home()
TEMP_DIR = os.path.join(HOME_DIR, "tmp")
DDOS_DEFENDER_DIR = "/opt/tempesta-ddos-defender"
DDOS_DEFENDER_CONFIG_DIR = "/etc/tempesta-ddos-defender"
J_CPU = "-j3"


logging.basicConfig(
    level=os.environ.get("LOGLEVEL", "INFO"),
    format="%(asctime)s %(levelname)-8s| %(name)s - %(message)s",
    datefmt=("%Y.%m.%d %H:%M:%S"),
)

logger = logging.getLogger("setup")


@dataclass
class CommandLineArgs:
    name: str
    verify: bool

    @classmethod
    def parse_args(cls) -> "CommandLineArgs":
        """
        Read command line arguments
        :return: key-value arguments
        """
        parser = argparse.ArgumentParser(
            description="Install full testing framework or some it's part",
            epilog="./setup.py --installation-name=full-setup",
            add_help=True,
        )
        parser.add_argument(
            "--name",
            type=str,
            default="full-setup",
            help="Select the name of the installation need to be installed",
        )
        parser.add_argument(
            "--verify",
            type=bool,
            default=False,
            help="Verify the installation",
        )
        return cls(**vars(parser.parse_args()))


class BaseModuleInstallation(metaclass=abc.ABCMeta):
    @staticmethod
    def shell(
        cmd: str,
        hint: Optional[str] = None,
        capture_output: bool = False,
        cwd: Optional[str] = None,
    ):
        """
        Executes a shell command and logs its status.

        Args:
            cmd (str): The shell command to execute.
            hint (Optional[str]): A descriptive hint for logging purposes. If not provided,
                                    defaults to `cmd`.
            capture_output (bool): If True, captures stdout and stderr of the subprocess.
            cwd (Optional[str]): The working directory in which to execute the command.

        Raises:
            RuntimeError: If the command exits with a non-zero return code.

        Logs:
            - "[start]" when execution begins.
            - "[fail]" on failure, including the return code and captured output
                        if `capture_output` is True.
            - "[ok]" when the command completes successfully.
        """

        if hint is None:
            hint = cmd

        logger.info(f"[{YELLOW}start{RESET}] {hint}")
        result = subprocess.run(cmd, shell=True, text=True, capture_output=capture_output, cwd=cwd)

        if result.returncode != 0:
            logger.error(f"[{RED}fail{RESET}] {hint} - '{cmd}'")
            logger.error(f"[{RED}fail{RESET}]return code {result.returncode}")

            if capture_output:
                logger.error(f"[{RED}fail{RESET}] {result.stderr}")
                logger.error(f"[{RED}fail{RESET}] {result.stdout}")

            raise RuntimeError("Subprocess error")

        logger.info(f"[{GREEN}ok{RESET}] {hint}")

    @classmethod
    @abc.abstractmethod
    def name(cls) -> str:
        """
        Name of the module. Should be the same as an attribute in the CommandLineArgs
        """

    def prepare(self):
        """
        Create temporary dirs, verify system sutability
        """

    @abc.abstractmethod
    def install(self):
        """
        Install the module
        """

    def after_cleanup(self):
        """
        Clean temporary data or some artifacts after installation
        """

    @abc.abstractmethod
    def test(self):
        """
        Verify that the module is installed and work correctly
        """


class InstallationInTempDir(BaseModuleInstallation, metaclass=abc.ABCMeta):
    def prepare(self):
        os.mkdir(TEMP_DIR)

    def after_cleanup(self):
        shutil.rmtree(TEMP_DIR)


class GroupInstallation(BaseModuleInstallation, metaclass=abc.ABCMeta):
    modules: list[BaseModuleInstallation]

    def prepare(self):
        for module_class in self.modules:
            module = module_class()
            module.prepare()

    def install(self):
        for module_class in self.modules:
            module = module_class()
            module.install()

    def after_cleanup(self):
        for module_class in self.modules:
            module = module_class()
            module.after_cleanup()

    def test(self):
        for module_class in self.modules:
            module = module_class()
            module.test()


class InstallAdditionalPackages(BaseModuleInstallation):
    def name(self) -> str:
        return "addtional_packages"

    def install(self):
        self.shell(
            "sudo apt install libtool net-tools apache2-utils "
            "autoconf unzip libtemplate-perl tcpdump util-linux -y"
        )

    def test(self):
        pass


class InstallNginx(BaseModuleInstallation):
    def name(self) -> str:
        return "nginx"

    def install(self):
        self.shell(
            "sudo apt install nginx libnginx-mod-http-echo ", "Install required Nginx packages"
        )
        # stop and disable installed nginx
        self.shell("sudo systemctl stop nginx", "stop nginx", capture_output=True)
        self.shell("sudo systemctl disable nginx", "disable nginx", capture_output=True)

    def test(self):
        self.shell("service nginx start")
        response = self.shell("curl http://localhost")

        if "200 - OK" not in response:
            raise ValueError("Failed to start nginx. Nginx was not installed correctly")

        self.shell("service nginx stop")


class InstallPython(BaseModuleInstallation):
    def name(self) -> str:
        return "python"

    def install(self):
        self.shell(
            "sudo add-apt-repository ppa:deadsnakes/ppa -y",
            "Append python3.10 repository",
            capture_output=True,
        )
        self.shell(
            "sudo apt update -y", "python3-pip python3.10 repository update", capture_output=True
        )
        self.shell("sudo apt install python3.10 -y", "install python3.10", capture_output=True)
        self.shell(
            "sudo apt install python3.10-venv -y", "install python3.10 venv", capture_output=True
        )

        self.shell("python3.10 -m venv env", "install virtual env")
        self.shell(". env/bin/activate", "Start virtual env")
        self.shell(
            "env/bin/python3 -m pip install -r requirements.txt", "install python requirements.tx"
        )

    def test(self):
        pass


class InstallPreCommit(BaseModuleInstallation):
    @classmethod
    def name(cls) -> str:
        return "precommit"

    def install(self):
        try:
            self.shell("env/bin/pre-commit install", "install pre-commit")
            self.shell("env/bin/pre-commit autoupdate", "autoupdate pre-commit")
        except RuntimeError:
            logger.info(
                "If you are not using this machine for development, you can ignore this error."
            )

    def test(self):
        pass


class InstallGit(BaseModuleInstallation):
    @classmethod
    def name(cls) -> str:
        return "git"

    def install(self):
        try:
            self.shell("git config blame.ignoreRevsFile .git-blame-ignore-revs")
        except RuntimeError:
            logger.info(
                "If you are not using this machine for development, you can ignore this error."
            )

    def test(self):
        pass


class InstallPerfTools(InstallationInTempDir):
    @classmethod
    def name(cls) -> str:
        return "perftools"

    def install(self):
        build_path = os.path.join(TEMP_DIR, "tls_perf")

        self.shell(f"git clone https://github.com/tempesta-tech/tls-perf.git {build_path}")
        self.shell(f"make {J_CPU}", cwd=build_path)
        compile_dir = os.path.join(build_path, "tls-perf")
        self.shell(f"sudo cp {compile_dir} /bin/tls-perf")

    def test(self):
        pass


class InstallWRK(InstallationInTempDir):
    @classmethod
    def name(cls) -> str:
        return "wrk"

    def install(self):
        build_path = os.path.join(TEMP_DIR, "wrk")
        self.shell(f"git clone https://github.com/wg/wrk.git {build_path}")
        self.shell(f"make {J_CPU}", cwd=build_path)
        compile_dir = os.path.join(build_path, "wrk")
        self.shell(f"sudo cp {compile_dir} /bin/wrk")

    def test(self):
        pass


class InstallH2Spec(InstallationInTempDir):
    @classmethod
    def name(cls) -> str:
        return "h2spec"

    def install(self):
        self.shell("sudo apt install golang-go -y")
        build_path = os.path.join(TEMP_DIR, "h2spec")

        self.shell(f"git clone https://github.com/tempesta-tech/h2spec.git {build_path}")
        self.shell(f"make {J_CPU}", cwd=build_path)
        compile_dir = os.path.join(build_path, "h2spec")
        self.shell(f"sudo cp {compile_dir} /usr/bin/h2spec")

    def test(self):
        pass


class InstallGFlood(InstallationInTempDir):
    @classmethod
    def name(cls) -> str:
        return "gflood"

    def install(self):
        build_path = os.path.join(TEMP_DIR, "gflood")
        os.mkdir(build_path)
        self.shell(f"cp tools/gflood/main.go {build_path}/")
        self.shell("go mod init gflood", cwd=build_path)
        self.shell("go mod tidy", cwd=build_path)
        self.shell("go build", cwd=build_path)
        compile_dir = os.path.join(build_path, "gflood")
        self.shell(f"sudo cp {compile_dir} /usr/bin/gflood")

    def test(self):
        pass


class InstallCtrlFramesFlood(InstallationInTempDir):
    @classmethod
    def name(cls) -> str:
        return "ctrl_frames_flood"

    def install(self):
        build_path = os.path.join(TEMP_DIR, "ctrl_frames_flood")
        os.mkdir(build_path)

        self.shell(f"cp tools/ctrl_frames_flood/main.go {build_path}/")
        self.shell("go mod init ctrl_frames_flood", cwd=build_path)
        self.shell("go mod tidy", cwd=build_path)
        self.shell("go build", cwd=build_path)
        compile_dir = os.path.join(build_path, "ctrl_frames_flood")
        self.shell(f"sudo cp {compile_dir} /usr/bin/ctrl_frames_flood")

    def test(self):
        pass


class InstallGUtils(BaseModuleInstallation):
    @classmethod
    def name(cls) -> str:
        return "gutils"

    def install(self):
        self.shell("sudo go build -o /usr/bin/ratecheck ./gutils/cmd/ratecheck/main.go")

    def test(self):
        pass


class InstallCurl(InstallationInTempDir):
    @classmethod
    def name(cls) -> str:
        return "curl"

    def install(self):
        build_path = os.path.join(TEMP_DIR, "curl")
        """
        nghttp2-client libnghttp2-dev nghttp2-client
        """
        self.shell(
            f"git clone --depth=1 --branch curl-7_85_0 https://github.com/curl/curl.git {build_path}"
        )
        self.shell("autoreconf -fi", cwd=build_path)
        self.shell("./configure --with-openssl --with-nghttp2 --prefix /usr/local", cwd=build_path)
        self.shell(f"make {J_CPU}", cwd=build_path)
        self.shell("sudo make install", cwd=build_path)
        self.shell("sudo ldconfig", cwd=build_path)

    def test(self):
        pass


class InstallLXC(BaseModuleInstallation):
    @classmethod
    def name(cls) -> str:
        return "lxc"

    def install(self):
        self.shell("apt install lxc")
        self.shell("sudo snap install lxd")
        self.shell("sudo lxd init --auto")

    def test(self):
        pass


class InstallTempestaSiteStage(BaseModuleInstallation):
    @classmethod
    def name(cls) -> str:
        return "tempesta_site_stage"

    def install(self):
        self.shell(
            "env/bin/python3 tempesta-tech.com/container/lxc/create.py "
            "--type=stage "
            f"--proxy=0.0.0.0:{cfg.get('Server', 'website_port')}"
        )

    def test(self):
        pass


class InstallDocker(BaseModuleInstallation):
    @classmethod
    def name(cls) -> str:
        return "docker"

    def install(self):
        self.shell("sudo apt install docker.io -y", "Docker install")

    def test(self):
        pass


class InstallClickHouse(BaseModuleInstallation):
    @classmethod
    def name(cls) -> str:
        return "clickhouse"

    def install(self):
        build_path = os.path.join(TEMP_DIR, "clickhouse-install")
        os.mkdir(build_path)
        self.shell("sudo apt install apt-transport-https ca-certificates gnupg -y", cwd=build_path)
        self.shell(
            "curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' | sudo gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg",
            cwd=build_path,
        )
        self.shell(
            'ARCH=$(dpkg --print-architecture); echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=${ARCH}] '
            'https://packages.clickhouse.com/deb stable main" | sudo tee /etc/apt/sources.list.d/clickhouse.list',
            cwd=build_path,
        )
        self.shell("sudo apt update")
        self.shell("sudo apt install clickhouse-server clickhouse-client -y")
        self.shell("sudo rm -f /etc/clickhouse-server/users.d/default-password.xml")
        self.shell("sudo systemctl enable clickhouse-server.service")
        self.shell("sudo systemctl start clickhouse-server.service")

    def test(self):
        pass


class InstallDDoSDefender(BaseModuleInstallation):
    @classmethod
    def name(cls) -> str:
        return "ddos-defender"

    def install(self):
        project_path = os.path.join(TEMP_DIR, "tempesta-source")
        self.shell(f"git clone https://github.com/tempesta-tech/tempesta {project_path}")
        self.shell(f"cp -R {project_path}/scripts/ddos_mitigation/ {DDOS_DEFENDER_DIR}")
        self.shell(f"mkdir {DDOS_DEFENDER_DIR}/source")
        self.shell(f"cp -R {project_path}/scripts/ddos_mitigation/ {DDOS_DEFENDER_DIR}/source")
        self.shell(f"python3.10 -m venv {DDOS_DEFENDER_DIR}/env")
        self.shell(
            f"{DDOS_DEFENDER_DIR}/env/bin/python3 -m pip install -r {DDOS_DEFENDER_DIR}/source/requirements.txt"
        )
        self.shell(f"mkdir {DDOS_DEFENDER_CONFIG_DIR}")
        self.shell(f"touch {DDOS_DEFENDER_CONFIG_DIR}/allow_user_agents.txt")
        self.shell(f"cp {DDOS_DEFENDER_DIR}/source/example.env {DDOS_DEFENDER_CONFIG_DIR}/app.env")

    def test(self):
        pass


class FullSetupGroup(GroupInstallation):
    modules = [
        InstallAdditionalPackages,
        InstallPython,
        InstallPreCommit,
        InstallGit,
        InstallNginx,
        InstallLXC,
        InstallDocker,
        InstallPerfTools,
        InstallWRK,
        InstallCurl,
        InstallH2Spec,
        InstallGFlood,
        InstallGUtils,
        InstallCtrlFramesFlood,
        InstallTempestaSiteStage,
        InstallClickHouse,
        InstallDDoSDefender,
    ]

    def name(self) -> str:
        return "full_setup"


def main():
    available_installations = [
        InstallAdditionalPackages,
        InstallPython,
        InstallPreCommit,
        InstallGit,
        InstallNginx,
        InstallLXC,
        InstallDocker,
        InstallPerfTools,
        InstallWRK,
        InstallCurl,
        InstallH2Spec,
        InstallGFlood,
        InstallGUtils,
        InstallCtrlFramesFlood,
        InstallTempestaSiteStage,
        InstallClickHouse,
        InstallDDoSDefender,
        FullSetupGroup,
    ]
    available_installations_map = {item.name(): item() for item in available_installations}

    args = CommandLineArgs.parse_args()
    module_class = available_installations_map.get(args.name)

    if not module_class:
        names = ", ".join([i for i in available_installations_map.keys()])
        print(f"Installation with name = `{args.name}` is not found. Available options: {names}")
        exit(1)

    module = module_class()
    module.prepare()
    module.install()
    module.after_cleanup()

    if args.verify:
        module.test()


if __name__ == "__main__":
    main()
