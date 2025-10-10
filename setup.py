#!/usr/bin/env python3

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import logging
import os
import shutil
import subprocess
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

J_CPU = "-j3"


logging.basicConfig(
    level=os.environ.get("LOGLEVEL", "INFO"),
    format="%(asctime)s %(levelname)-8s| %(name)s - %(message)s",
    datefmt=("%Y.%m.%d %H:%M:%S"),
)

logger = logging.getLogger("setup")


def shell(
    cmd: str, hint: Optional[str] = None, capture_output: bool = False, cwd: Optional[str] = None
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


def main():
    # required packages
    shell(
        (
            """
    sudo apt install python3-pip nginx libnginx-mod-http-echo libtool net-tools libssl-dev \
    apache2-utils nghttp2-client libnghttp2-dev autoconf unzip libtemplate-perl \
    tcpdump util-linux software-properties-common -y
    """
        ),
        "Install required packages",
    )

    # stop and disable installed nginx
    shell("sudo systemctl stop nginx", "stop nginx", capture_output=True)
    shell("sudo systemctl disable nginx", "disable nginx", capture_output=True)

    # python
    shell(
        "sudo add-apt-repository ppa:deadsnakes/ppa -y",
        "Append python3.10 repository",
        capture_output=True,
    )
    shell("sudo apt update -y", "python3.10 repository update", capture_output=True)
    shell("sudo apt install python3.10 -y", "install python3.10", capture_output=True)
    shell("sudo apt install python3.10-venv -y", "install python3.10 venv", capture_output=True)

    shell("python3.10 -m venv env", "install virtual env")
    shell(". env/bin/activate", "Start virtual env")
    shell("env/bin/python3 -m pip install -r requirements.txt", "install python requirements.tx")

    # precommit
    try:
        shell("env/bin/pre-commit install", "install pre-commit")
        shell("env/bin/pre-commit autoupdate", "autoupdate pre-commit")
    except RuntimeError:
        logger.info("If you are not using this machine for development, you can ignore this error.")

    # git
    try:
        shell("git config blame.ignoreRevsFile .git-blame-ignore-revs")
    except RuntimeError:
        logger.info("If you are not using this machine for development, you can ignore this error.")

    if not os.path.exists(TEMP_DIR):
        os.mkdir(TEMP_DIR)

    # tls-perf
    build_path = os.path.join(TEMP_DIR, "tls_perf")
    if os.path.exists(build_path):
        shutil.rmtree(build_path)
    shell(f"git clone https://github.com/tempesta-tech/tls-perf.git {build_path}")
    shell(f"make {J_CPU}", cwd=build_path)
    compile_dir = os.path.join(build_path, "tls-perf")
    shell(f"sudo cp {compile_dir} /bin/tls-perf")
    if os.path.exists(build_path):
        shutil.rmtree(build_path)

    # wrk
    build_path = os.path.join(TEMP_DIR, "wrk")
    if os.path.exists(build_path):
        shutil.rmtree(build_path)
    shell(f"git clone https://github.com/wg/wrk.git {build_path}")
    shell(f"make {J_CPU}", cwd=build_path)
    compile_dir = os.path.join(build_path, "wrk")
    shell(f"sudo cp {compile_dir} /bin/wrk")
    if os.path.exists(build_path):
        shutil.rmtree(build_path)

    # h2spec
    shell("sudo apt install golang-go -y")
    build_path = os.path.join(TEMP_DIR, "h2spec")
    if os.path.exists(build_path):
        shutil.rmtree(build_path)
    shell(f"git clone https://github.com/tempesta-tech/h2spec.git {build_path}")
    shell(f"make {J_CPU}", cwd=build_path)
    compile_dir = os.path.join(build_path, "h2spec")
    shell(f"sudo cp {compile_dir} /usr/bin/h2spec")
    if os.path.exists(build_path):
        shutil.rmtree(build_path)

    # gflood - CONTINUATION frame flooder
    build_path = os.path.join(TEMP_DIR, "gflood")
    if os.path.exists(build_path):
        shutil.rmtree(build_path)
    os.mkdir(build_path)
    shell(f"cp tools/gflood/main.go {build_path}/")
    shell("go mod init gflood", cwd=build_path)
    shell("go mod tidy", cwd=build_path)
    shell("go build", cwd=build_path)
    compile_dir = os.path.join(build_path, "gflood")
    shell(f"sudo cp {compile_dir} /usr/bin/gflood")
    if os.path.exists(build_path):
        shutil.rmtree(build_path)

    # ctrl_frames_flood - ctrl frame flooder
    build_path = os.path.join(TEMP_DIR, "ctrl_frames_flood")
    if os.path.exists(build_path):
        shutil.rmtree(build_path)
    os.mkdir(build_path)
    shell(f"cp tools/ctrl_frames_flood/main.go {build_path}/")
    shell("go mod init ctrl_frames_flood", cwd=build_path)
    shell("go mod tidy", cwd=build_path)
    shell("go build", cwd=build_path)
    compile_dir = os.path.join(build_path, "ctrl_frames_flood")
    shell(f"sudo cp {compile_dir} /usr/bin/ctrl_frames_flood")
    if os.path.exists(build_path):
        shutil.rmtree(build_path)

    # gutils - Common golang utils
    shell("sudo go build -o /usr/bin/ratecheck ./gutils/cmd/ratecheck/main.go")

    # curl
    build_path = os.path.join(TEMP_DIR, "curl")
    if os.path.exists(build_path):
        shutil.rmtree(build_path)
    shell(f"git clone --depth=1 --branch curl-7_85_0 https://github.com/curl/curl.git {build_path}")
    shell("autoreconf -fi", cwd=build_path)
    shell("./configure --with-openssl --with-nghttp2 --prefix /usr/local", cwd=build_path)
    shell(f"make {J_CPU}", cwd=build_path)
    shell("sudo make install", cwd=build_path)
    shell("sudo ldconfig", cwd=build_path)
    if os.path.exists(build_path):
        shutil.rmtree(build_path)

    # docker
    shell("sudo apt install docker.io -y", "Docker install")

    # ClickHouse
    build_path = os.path.join(TEMP_DIR, "clickhouse-install")
    if os.path.exists(build_path):
        shutil.rmtree(build_path)
    os.mkdir(build_path)
    shell("sudo apt install apt-transport-https ca-certificates gnupg -y", cwd=build_path)
    shell(
        "curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' | sudo gpg --dearmor -o /usr/share/keyrings/clickhouse-keyring.gpg",
        cwd=build_path,
    )
    shell(
        'ARCH=$(dpkg --print-architecture); echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=${ARCH}] https://packages.clickhouse.com/deb stable main" | sudo tee /etc/apt/sources.list.d/clickhouse.list',
        cwd=build_path,
    )
    shell("sudo apt update")
    shell("sudo apt install clickhouse-server clickhouse-client -y")
    shell("sudo rm -f /etc/clickhouse-server/users.d/default-password.xml")
    shell("sudo systemctl enable clickhouse-server.service")
    shell("sudo systemctl start clickhouse-server.service")

    if os.path.exists(build_path):
        shutil.rmtree(build_path)

    if not os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)


if __name__ == "__main__":
    main()
