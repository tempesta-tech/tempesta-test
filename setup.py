#!/usr/bin/env python3
"""Install the Tempesta test environment. Each module can be run alone: ./setup.py --name=curl"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2025-2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

import abc
import argparse
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional

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
    # force requirements installation
    force: bool

    @classmethod
    def parse_args(cls) -> "CommandLineArgs":
        parser = argparse.ArgumentParser(
            description="Install full testing framework or some it's part",
            epilog="./setup.py --name=full-setup",
            add_help=True,
        )
        parser.add_argument("--name", type=str, default="full-setup")
        parser.add_argument("--verify", type=bool, default=False)
        parser.add_argument("--force", type=bool, default=False)
        return cls(**vars(parser.parse_args()))


class BaseModuleInstallation(metaclass=abc.ABCMeta):
    """One installable piece of the test environment. `name` is the --name CLI value."""

    name: str
    red = "\033[91m"
    green = "\033[92m"
    yellow = "\033[93m"
    reset = "\033[0m"
    force_install: bool = False

    @classmethod
    def shell(cls, cmd: str, hint: Optional[str] = None, cwd: Optional[str] = None):
        hint = hint or cmd
        logger.info(f"[{cls.yellow}start{cls.reset}] {hint}")
        result = subprocess.run(cmd, shell=True, text=True, cwd=cwd)
        if result.returncode != 0:
            logger.error(f"[{cls.red}fail{cls.reset}] {hint} - '{cmd}'")
            raise RuntimeError("Subprocess error")
        logger.info(f"[{cls.green}ok{cls.reset}] {hint}")

    @staticmethod
    def dpkg_version(package: str) -> Optional[str]:
        result = subprocess.run(
            ["dpkg-query", "-W", "-f=${Status} ${Version}", package],
            text=True,
            capture_output=True,
        )
        if result.returncode != 0 or "install ok installed" not in result.stdout:
            return None
        return result.stdout.strip().rsplit(" ", 1)[-1]

    def installed(self) -> bool:
        """True if the module is already present and can be skipped."""
        return False

    def prepare(self):
        pass

    def after_cleanup(self):
        pass

    def install(self):
        if self.installed() and not self.force_install:
            logger.info(f"[{self.yellow}skip{self.reset}] {self.name}")
            return
        self.do_install()

    @abc.abstractmethod
    def do_install(self):
        pass

    def test(self):
        if not self.installed():
            raise RuntimeError(f"{self.name} is not installed")


class InstallationInTempDir(BaseModuleInstallation, metaclass=abc.ABCMeta):
    # Build artifacts go to ~/tmp; add that path to .gitignore.
    temp_dir = os.path.join(os.path.expanduser("~"), "tmp")
    jobs = "-j3"

    def prepare(self):
        os.makedirs(self.temp_dir, exist_ok=True)

    def after_cleanup(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)


class GroupInstallation(BaseModuleInstallation, metaclass=abc.ABCMeta):
    modules: list

    def prepare(self):
        for module in self.modules:
            module().prepare()

    def do_install(self):
        for module in self.modules:
            module().install()

    def after_cleanup(self):
        for module in self.modules:
            module().after_cleanup()

    def test(self):
        for module in self.modules:
            module().test()


class InstallAdditionalPackages(BaseModuleInstallation):
    name = "additional_packages"
    packages = [
        "python3-pip",
        "libtool",
        "net-tools",
        "libssl-dev",
        "apache2-utils",
        "nghttp2-client",
        "libnghttp2-dev",
        "autoconf",
        "automake",
        "pkg-config",
        "unzip",
        "libtemplate-perl",
        "tcpdump",
        "util-linux",
        "software-properties-common",
    ]

    def installed(self) -> bool:
        return all(self.dpkg_version(package) for package in self.packages)

    def do_install(self):
        self.shell(f"sudo apt install {' '.join(self.packages)} -y")


class InstallNginx(BaseModuleInstallation):
    name = "nginx"

    def installed(self) -> bool:
        return bool(self.dpkg_version("nginx") and self.dpkg_version("libnginx-mod-http-echo"))

    def do_install(self):
        self.shell("sudo apt install nginx libnginx-mod-http-echo -y")
        # Tests start nginx themselves; keep the system unit from occupying :80.
        self.shell("sudo systemctl stop nginx")
        self.shell("sudo systemctl disable nginx")


class InstallPython(BaseModuleInstallation):
    name = "python"

    def installed(self) -> bool:
        return os.path.exists("env/bin/python3")

    def do_install(self):
        if os.path.exists("env"):
            shutil.rmtree("env")
        self.shell("python3 -m venv env")
        self.shell("env/bin/python3 -m pip install -r requirements.txt")


class InstallPreCommit(BaseModuleInstallation):
    """Optional. Fails softly on machines that are not used for development."""

    name = "precommit"

    def installed(self) -> bool:
        return os.path.exists(".git/hooks/pre-commit")

    def do_install(self):
        try:
            self.shell("env/bin/pre-commit install")
            self.shell("env/bin/pre-commit autoupdate")
        except RuntimeError:
            logger.info("If you are not using this machine for development, ignore this error.")


class InstallGit(BaseModuleInstallation):
    """Optional git blame config for developers."""

    name = "git"

    def do_install(self):
        try:
            self.shell("git config blame.ignoreRevsFile .git-blame-ignore-revs")
        except RuntimeError:
            logger.info("If you are not using this machine for development, ignore this error.")


class InstallPerfTools(InstallationInTempDir):
    """tls-perf from tempesta-tech/tls-perf."""

    name = "perftools"

    def installed(self) -> bool:
        return os.path.exists("/bin/tls-perf")

    def do_install(self):
        path = os.path.join(self.temp_dir, "tls_perf")
        if os.path.exists(path):
            shutil.rmtree(path)  # git clone fails if the dest already exists
        self.shell(f"git clone https://github.com/tempesta-tech/tls-perf.git {path}")
        self.shell(f"make {self.jobs}", cwd=path)
        self.shell(f"sudo cp {path}/tls-perf /bin/tls-perf")


class InstallWRK(InstallationInTempDir):
    name = "wrk"

    def installed(self) -> bool:
        return os.path.exists("/bin/wrk")

    def do_install(self):
        path = os.path.join(self.temp_dir, "wrk")
        if os.path.exists(path):
            shutil.rmtree(path)
        self.shell(f"git clone https://github.com/wg/wrk.git {path}")
        self.shell(f"make {self.jobs}", cwd=path)
        self.shell(f"sudo cp {path}/wrk /bin/wrk")


class InstallH2Spec(InstallationInTempDir):
    name = "h2spec"

    def installed(self) -> bool:
        return os.path.exists("/usr/bin/h2spec")

    def do_install(self):
        if not self.dpkg_version("golang-go"):
            self.shell("sudo apt install golang-go -y")
        path = os.path.join(self.temp_dir, "h2spec")
        if os.path.exists(path):
            shutil.rmtree(path)
        self.shell(f"git clone https://github.com/tempesta-tech/h2spec.git {path}")
        self.shell(f"make {self.jobs}", cwd=path)
        self.shell(f"sudo cp {path}/h2spec /usr/bin/h2spec")


class InstallGFlood(InstallationInTempDir):
    """HTTP/2 CONTINUATION frame flooder from tools/gflood."""

    name = "gflood"

    def installed(self) -> bool:
        return os.path.exists("/usr/bin/gflood")

    def do_install(self):
        path = os.path.join(self.temp_dir, "gflood")
        if os.path.exists(path):
            shutil.rmtree(path)
        os.makedirs(path)
        self.shell(f"cp tools/gflood/main.go {path}/")
        self.shell("go mod init gflood", cwd=path)
        self.shell("go mod tidy", cwd=path)
        self.shell("go build", cwd=path)
        self.shell(f"sudo cp {path}/gflood /usr/bin/gflood")


class InstallCtrlFramesFlood(InstallationInTempDir):
    """HTTP/2 control-frame flooder from tools/ctrl_frames_flood."""

    name = "ctrl_frames_flood"

    def installed(self) -> bool:
        return os.path.exists("/usr/bin/ctrl_frames_flood")

    def do_install(self):
        path = os.path.join(self.temp_dir, "ctrl_frames_flood")
        if os.path.exists(path):
            shutil.rmtree(path)
        os.makedirs(path)
        self.shell(f"cp tools/ctrl_frames_flood/main.go {path}/")
        self.shell("go mod init ctrl_frames_flood", cwd=path)
        self.shell("go mod tidy", cwd=path)
        self.shell("go build", cwd=path)
        self.shell(f"sudo cp {path}/ctrl_frames_flood /usr/bin/ctrl_frames_flood")


class InstallRudy(InstallationInTempDir):
    """Slowloris/RUDY tool. `commit` is the pinned darkweak/rudy master HEAD."""

    name = "rudy"
    repo = "https://github.com/darkweak/rudy.git"
    commit = "feba27c0a73329e9f0f8c6709d7ed7ad78faa922"

    def installed(self) -> bool:
        return os.path.exists("/usr/bin/rudy")

    def do_install(self):
        path = os.path.join(self.temp_dir, "rudy")
        if os.path.exists(path):
            shutil.rmtree(path)
        self.shell(f"git clone {self.repo} {path}")
        self.shell(f"git checkout {self.commit}", cwd=path)
        # rudy's go.mod needs a newer toolchain than many distro Go packages.
        self.shell("GOTOOLCHAIN=go1.26.0 go build -o rudy rudy.go", cwd=path)
        self.shell(f"sudo cp {path}/rudy /usr/bin/rudy")


class InstallGUtils(BaseModuleInstallation):
    """ratecheck from tools/gutils."""

    name = "gutils"

    def installed(self) -> bool:
        return os.path.exists("/usr/bin/ratecheck")

    def do_install(self):
        self.shell("sudo go build -o /usr/bin/ratecheck ./tools/gutils/cmd/ratecheck/main.go")


class InstallCurl(InstallationInTempDir):
    """curl 7.85.0 with nghttp2, installed to /usr/local (tests need this build)."""

    name = "curl"

    def installed(self) -> bool:
        return os.path.exists("/usr/local/bin/curl")

    def do_install(self):
        path = os.path.join(self.temp_dir, "curl")
        if os.path.exists(path):
            shutil.rmtree(path)
        self.shell(
            "sudo apt install autoconf automake libtool pkg-config "
            "libssl-dev nghttp2-client libnghttp2-dev -y"
        )
        self.shell(
            f"git clone --depth=1 --branch curl-7_85_0 https://github.com/curl/curl.git {path}"
        )
        self.shell("autoreconf -fi", cwd=path)
        self.shell("./configure --with-openssl --with-nghttp2 --prefix /usr/local", cwd=path)
        self.shell(f"make {self.jobs}", cwd=path)
        self.shell("sudo make install", cwd=path)
        self.shell("sudo ldconfig", cwd=path)


class InstallDocker(BaseModuleInstallation):
    name = "docker"

    def installed(self) -> bool:
        return bool(self.dpkg_version("docker.io"))

    def do_install(self):
        self.shell("sudo apt install docker.io -y")


class InstallClickHouse(InstallationInTempDir):
    name = "clickhouse"

    def installed(self) -> bool:
        return bool(
            self.dpkg_version("clickhouse-server") and self.dpkg_version("clickhouse-client")
        )

    def do_install(self):
        self.shell("sudo apt install apt-transport-https ca-certificates gnupg -y")
        # gpg --dearmor asks "Overwrite?" if the keyring file already exists.
        self.shell("sudo rm -f /usr/share/keyrings/clickhouse-keyring.gpg")
        self.shell(
            "curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' | "
            "sudo gpg --batch --yes --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg"
        )
        self.shell(
            'ARCH=$(dpkg --print-architecture); echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=${ARCH}] '
            'https://packages.clickhouse.com/deb stable main" | sudo tee /etc/apt/sources.list.d/clickhouse.list'
        )
        self.shell("sudo apt update")
        # postinst uses raw `read` for the default password; DEBIAN_FRONTEND is not enough.
        self.shell(
            "sudo CLICKHOUSE_SKIP_USER_SETUP=1 DEBIAN_FRONTEND=noninteractive "
            "apt install clickhouse-server clickhouse-client -y"
        )
        self.shell("sudo rm -f /etc/clickhouse-server/users.d/default-password.xml")
        self.shell("sudo systemctl enable clickhouse-server.service")
        self.shell("sudo systemctl start clickhouse-server.service")


class InstallWebShield(InstallationInTempDir):
    """Tempesta WebShield. `commit` is the pinned tempesta-tech/webshield main HEAD."""

    name = "webshield"
    repo = "https://github.com/tempesta-tech/webshield.git"
    commit = "dfb5ddeb4b1ff30e38a29eb2d5e249013eace17c"
    install_dir = "/opt/tempesta/webshield"
    config_dir = "/etc/tempesta/webshield"
    tft_dir = "/etc/tempesta/fw/tft"
    tfh_dir = "/etc/tempesta/fw/tfh"

    def installed(self) -> bool:
        return os.path.exists(os.path.join(self.install_dir, "source"))

    def do_install(self):
        path = os.path.join(self.temp_dir, "webshield")
        if os.path.exists(path):
            shutil.rmtree(path)
        if not self.dpkg_version("ipset"):
            self.shell("sudo apt install -y ipset")
        self.shell(f"git clone {self.repo} {path}")
        self.shell(f"git checkout {self.commit}", cwd=path)
        self.shell(f"sudo rm -rf {self.install_dir}")
        self.shell(f"sudo mkdir -p {self.install_dir}/source")
        self.shell(f"sudo cp -R {path}/. {self.install_dir}/source/")
        self.shell(f"sudo python3 -m venv {self.install_dir}/venv")
        self.shell(
            f"sudo {self.install_dir}/venv/bin/python3 -m pip install -r "
            f"{self.install_dir}/source/requirements.txt"
        )
        # tft/tfh dirs are included from the Tempesta config used by DDoS tests.
        self.shell(f"sudo mkdir -p {self.config_dir} {self.tft_dir} {self.tfh_dir}")
        self.shell(f"sudo touch {self.config_dir}/allow_user_agents.txt")
        self.shell(f"sudo touch {self.tft_dir}/blocked.conf {self.tfh_dir}/blocked.conf")
        self.shell(f"sudo cp -n {self.install_dir}/source/example.env {self.config_dir}/app.env")
        self.shell(
            f"sudo cp {self.install_dir}/source/deployment/tempesta-webshield.service "
            "/etc/systemd/system/tempesta-webshield.service"
        )
        self.shell("sudo systemctl daemon-reload")
        self.shell("sudo systemctl enable tempesta-webshield.service")


class FullSetupGroup(GroupInstallation):
    """Default --name: install every module below."""

    name = "full-setup"
    modules = [
        InstallAdditionalPackages,
        InstallPython,
        InstallPreCommit,
        InstallGit,
        InstallNginx,
        InstallDocker,
        InstallPerfTools,
        InstallWRK,
        InstallCurl,
        InstallH2Spec,
        InstallGFlood,
        InstallGUtils,
        InstallCtrlFramesFlood,
        InstallRudy,
        InstallClickHouse,
        InstallWebShield,
    ]


def main():
    available = [
        InstallAdditionalPackages,
        InstallPython,
        InstallPreCommit,
        InstallGit,
        InstallNginx,
        InstallDocker,
        InstallPerfTools,
        InstallWRK,
        InstallCurl,
        InstallH2Spec,
        InstallGFlood,
        InstallGUtils,
        InstallCtrlFramesFlood,
        InstallRudy,
        InstallClickHouse,
        InstallWebShield,
        FullSetupGroup,
    ]
    available_map = {item.name: item for item in available}
    args = CommandLineArgs.parse_args()
    module_class = available_map.get(args.name)
    if not module_class:
        print(f"Installation `{args.name}` not found. Available: {', '.join(available_map)}")
        exit(1)

    module = module_class(force=args.force)
    module.prepare()
    module.install()
    module.after_cleanup()
    if args.verify:
        module.test()


if __name__ == "__main__":
    main()
