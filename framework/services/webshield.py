"""Tempesta WebShield process wrapper for tests.

Starts the WebShield daemon against ClickHouse access logs, writes TFT/TFH
include files, and reloads Tempesta FW when hashes are blocked.

Detector model (tft_rps / tfh_rps):
    Each monitoring tick compares two time slices of
    ``BLOCKING_WINDOW_DURATION_SEC`` (``users_before`` then ``users_after``,
    with a one-window gap). A fingerprint is blocked only when
    ``users_before`` is non-empty and the key overlap is below
    ``*_INTERSECTION_PERCENT``. Empty ``users_before`` means no block.

Real training:
    Sleeps ``TRAINING_MODE_DURATION_MIN``, then sets
    ``threshold = mean + stddev`` from request *counts* over that whole
    period. Monitoring then applies the same number to short blocking
    windows. High training volume makes 3s curl slices miss HAVING, so
    ``users_before`` stays empty.

``start()`` returns as soon as the pid exists. Use ``wait_until_started``
(release-monitor log) and ``wait_until_tick`` (next risky-users log).
"""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

import asyncio
import json
import multiprocessing
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from framework.helpers import remote, tf_cfg, util
from framework.services import stateful


class TrainingMode(str, Enum):
    """WebShield TRAINING_MODE. Real mode delays monitoring until the sleep ends."""

    OFF = "off"
    HISTORICAL = "historical"
    REAL = "real"


class Detector(str, Enum):
    IP_RPS = "ip_rps"
    IP_TIME = "ip_time"
    IP_ERRORS = "ip_errors"
    TFT_RPS = "tft_rps"
    TFT_TIME = "tft_time"
    TFT_ERRORS = "tft_errors"
    TFH_RPS = "tfh_rps"
    TFH_TIME = "tfh_time"
    TFH_ERRORS = "tfh_errors"
    GEOIP = "geoip"


class BlockingType(str, Enum):
    TFT = "tft"
    TFH = "tfh"
    IPSET = "ipset"
    NFTABLES = "nftables"


@dataclass(frozen=True)
class DetectorConfig:
    """Per-detector HAVING threshold and validate_model overlap percent."""

    rps_threshold: int = 1
    time_threshold: int = 1
    errors_threshold: int = 1
    rps_intersection_percent: int = 60


@dataclass(frozen=True)
class ClickHouseConfig:
    host: str = field(default_factory=lambda: tf_cfg.cfg.get("TFW_Logger", "ip"))
    port: int = field(
        default_factory=lambda: int(tf_cfg.cfg.get("TFW_Logger", "clickhouse_http_port"))
    )
    user: str = field(default_factory=lambda: tf_cfg.cfg.get("TFW_Logger", "clickhouse_username"))
    password: str = field(
        default_factory=lambda: tf_cfg.cfg.get("TFW_Logger", "clickhouse_password")
    )
    table: str = field(default_factory=lambda: tf_cfg.cfg.get("TFW_Logger", "clickhouse_table"))
    database: str = field(
        default_factory=lambda: tf_cfg.cfg.get("TFW_Logger", "clickhouse_database")
    )


@dataclass(frozen=True)
class WebShieldConfig:
    """WebShield AppConfig. ``to_env()`` writes the daemon .env file.

    Defaults are test-oriented: low RPS threshold, TFT-only, no training,
    no persistent-user whitelist, no Googlebot fetch.
    """

    training_mode: TrainingMode = TrainingMode.OFF
    training_mode_duration_min: int = 10
    detectors: tuple[Detector, ...] = (Detector.TFT_RPS,)
    blocking_types: tuple[BlockingType, ...] = (BlockingType.TFT,)
    # Monitoring slice. Real training still aggregates the whole minute.
    blocking_window_duration_sec: int = 10
    blocking_time_min: int = 60
    blocking_release_time_min: int = 1
    blocking_ipset_name: str = "tempesta_blocked_ips"
    persistent_users_allow: bool = False
    persistent_users_window_offset_min: int = 60
    persistent_users_window_duration_min: int = 60
    path_to_tft_config: str = "/tmp/tft/blocked.conf"
    path_to_tfh_config: str = "/tmp/tfh/blocked.conf"
    allowed_user_agents_file_path: str = "/tmp/allowed_user_agents.txt"
    # WebShield defaults to ["google"] and downloads bot ranges before training.
    bots_white_list_allowed: tuple[str, ...] = ()
    tempesta_executable_path: str = field(
        default_factory=lambda: tf_cfg.cfg.get("Tempesta", "srcdir") + "/scripts/tempesta.sh"
    )
    tempesta_config_path: str = field(
        default_factory=lambda: os.path.join(
            tf_cfg.cfg.get("Tempesta", "workdir"),
            tf_cfg.cfg.get("Tempesta", "config"),
        )
    )
    log_level: str = "DEBUG"
    tft: DetectorConfig = field(default_factory=DetectorConfig)
    tfh: DetectorConfig = field(default_factory=DetectorConfig)
    clickhouse: ClickHouseConfig = field(default_factory=ClickHouseConfig)

    def to_env(self) -> str:
        values = {
            "TRAINING_MODE": self.training_mode.value,
            "TRAINING_MODE_DURATION_MIN": self.training_mode_duration_min,
            "PATH_TO_TFT_CONFIG": self.path_to_tft_config,
            "PATH_TO_TFH_CONFIG": self.path_to_tfh_config,
            "CLICKHOUSE_HOST": self.clickhouse.host,
            "CLICKHOUSE_PORT": self.clickhouse.port,
            "CLICKHOUSE_USER": self.clickhouse.user,
            "CLICKHOUSE_PASSWORD": self.clickhouse.password,
            "CLICKHOUSE_TABLE_NAME": self.clickhouse.table,
            "CLICKHOUSE_DATABASE": self.clickhouse.database,
            "PERSISTENT_USERS_ALLOW": self.persistent_users_allow,
            "PERSISTENT_USERS_WINDOW_OFFSET_MIN": self.persistent_users_window_offset_min,
            "PERSISTENT_USERS_WINDOW_DURATION_MIN": self.persistent_users_window_duration_min,
            # pydantic-settings expects JSON for list/set fields.
            "DETECTORS": json.dumps([item.value for item in self.detectors]),
            "BLOCKING_TYPES": json.dumps([item.value for item in self.blocking_types]),
            "BLOCKING_WINDOW_DURATION_SEC": self.blocking_window_duration_sec,
            "BLOCKING_IPSET_NAME": self.blocking_ipset_name,
            "BLOCKING_TIME_MIN": self.blocking_time_min,
            "BLOCKING_RELEASE_TIME_MIN": self.blocking_release_time_min,
            "DETECTOR_TFT_RPS_DEFAULT_THRESHOLD": self.tft.rps_threshold,
            "DETECTOR_TFT_TIME_DEFAULT_THRESHOLD": self.tft.time_threshold,
            "DETECTOR_TFT_ERRORS_DEFAULT_THRESHOLD": self.tft.errors_threshold,
            "DETECTOR_TFT_RPS_INTERSECTION_PERCENT": self.tft.rps_intersection_percent,
            "DETECTOR_TFH_RPS_DEFAULT_THRESHOLD": self.tfh.rps_threshold,
            "DETECTOR_TFH_TIME_DEFAULT_THRESHOLD": self.tfh.time_threshold,
            "DETECTOR_TFH_ERRORS_DEFAULT_THRESHOLD": self.tfh.errors_threshold,
            "DETECTOR_TFH_RPS_INTERSECTION_PERCENT": self.tfh.rps_intersection_percent,
            "TEMPESTA_EXECUTABLE_PATH": self.tempesta_executable_path,
            "TEMPESTA_CONFIG_PATH": self.tempesta_config_path,
            "ALLOWED_USER_AGENTS_FILE_PATH": self.allowed_user_agents_file_path,
            "BOTS_WHITE_LIST_ALLOWED": json.dumps(list(self.bots_white_list_allowed)),
            "LOG_LEVEL": self.log_level,
        }
        return "".join(f"{key}={value}\n" for key, value in values.items())


class WebShield(stateful.Stateful):
    """Remote WebShield daemon: env file, include hashes, ClickHouse, reload."""

    def __init__(
        self,
        config: Optional[WebShieldConfig] = None,
        *,
        id_: str = "webshield",
        blocked_config: Optional[str] = None,
        env_path: str = "/tmp/webshield.env",
        log_path: str = "/tmp/webshield.log",
    ):
        super().__init__(id_=id_)
        self.config = config or WebShieldConfig()
        self.env_path = env_path
        self.log_path = log_path
        self.tft_dir = os.path.dirname(self.config.path_to_tft_config)
        self.tfh_dir = os.path.dirname(self.config.path_to_tfh_config)
        self.tempesta_tmpl_path = os.path.join(
            tf_cfg.cfg.get("Tempesta", "workdir"),
            tf_cfg.cfg.get("Tempesta", "tmp_config"),
        )
        duration = int(tf_cfg.cfg.get("General", "duration"))
        extra = self.training_duration_sec if self.config.training_mode != TrainingMode.OFF else 0
        # run_cmd still communicate()-waits; keep this above training + load.
        self.run_timeout = max(duration * 20, 180) + extra
        self.executable = tf_cfg.cfg.get("General", "webshield_executable")
        self.srcdir = tf_cfg.cfg.get("General", "webshield_srcdir")
        # Hash file the test reads; TFT vs TFH include depends on blocking_types.
        if blocked_config is not None:
            self.blocked_config = blocked_config
        elif self.config.blocking_types == (BlockingType.TFH,):
            self.blocked_config = self.config.path_to_tfh_config
        else:
            self.blocked_config = self.config.path_to_tft_config
        self._process: Optional[multiprocessing.Process] = None

    @property
    def blocking_window(self) -> int:
        return self.config.blocking_window_duration_sec

    @property
    def training_duration_sec(self) -> int:
        return self.config.training_mode_duration_min * 60

    def clear_stats(self) -> None:
        self._process = None

    def _stop_procedures(self) -> list[Callable]:
        return [self._stop]

    def _write_config(self) -> None:
        remote.tempesta.copy_file(filename=self.env_path, content=self.config.to_env())

    def _prepare_files(self) -> None:
        remote.tempesta.mkdir(self.tft_dir)
        remote.tempesta.mkdir(self.tfh_dir)
        remote.tempesta.copy_file(filename=self.config.path_to_tft_config, content="")
        remote.tempesta.copy_file(filename=self.config.path_to_tfh_config, content="")
        remote.tempesta.copy_file(filename=self.config.allowed_user_agents_file_path, content="")
        # Truncate so a previous run's log is not mistaken for monitoring start.
        remote.tempesta.copy_file(filename=self.log_path, content="")
        self._write_config()

    def restore_tempesta_tmpl(self) -> None:
        # tempesta.sh --start expands the live config into TFW_CFG_TMPL and then
        # deletes it. The kernel module still rereads that path on reload.
        remote.tempesta.run_cmd(f"cp {self.config.tempesta_config_path} {self.tempesta_tmpl_path}")

    @staticmethod
    def _run(
        executable: str,
        srcdir: str,
        config_path: str,
        log_path: str,
        tempesta_config: str,
        tempesta_tmpl: str,
        run_timeout: int,
    ) -> None:
        # --reload only sets TFW_CFG_PATH. Pass TFW_CFG_TMPL so the templater
        # writes expanded !include hashes where the kernel rereads them.
        # nohup + & : run_cmd still communicate()-waits and kills on timeout.
        # --log-level=DEBUG : CLI defaults to INFO and ignores env LOG_LEVEL.
        remote.tempesta.run_cmd(
            f"nohup {executable} {srcdir}/app.py --config={config_path} "
            f"--log-level=DEBUG >> {log_path} 2>&1 </dev/null &",
            is_blocking=False,
            timeout=run_timeout,
            env={
                "TFW_CFG_PATH": tempesta_config,
                "TFW_CFG_TMPL": tempesta_tmpl,
            },
        )

    async def run_start(self) -> None:
        self._prepare_files()
        self.restore_tempesta_tmpl()
        self._process = multiprocessing.Process(
            target=self._run,
            kwargs={
                "executable": self.executable,
                "srcdir": self.srcdir,
                "config_path": self.env_path,
                "log_path": self.log_path,
                "tempesta_config": self.config.tempesta_config_path,
                "tempesta_tmpl": self.tempesta_tmpl_path,
                "run_timeout": self.run_timeout,
            },
        )
        self._process.start()

        deadline = time.time() + 5
        while time.time() < deadline:
            if self.pid:
                return
            await asyncio.sleep(0.2)
        raise RuntimeError("WebShield is not running")

    def _stop(self) -> None:
        process = self._process
        if process is not None and process.is_alive():
            process.terminate()
            process.join(timeout=2)
            if process.is_alive():
                process.kill()
        self._process = None

        # nohup detaches app.py from the multiprocessing child; pkill by cmdline.
        remote.tempesta.run_cmd(
            "ps -eo pid,cmd | grep webshield | grep -v grep | awk '{print $1}' "
            "| xargs -r kill -9 || true"
        )
        for path in (
            self.config.path_to_tft_config,
            self.config.path_to_tfh_config,
            self.config.allowed_user_agents_file_path,
            self.env_path,
            self.log_path,
        ):
            remote.tempesta.remove_file(path)

    def read(self, path: Optional[str] = None) -> str:
        stdout, _ = remote.tempesta.run_cmd(f"cat {path or self.blocked_config} || true")
        return stdout.decode() if isinstance(stdout, bytes) else (stdout or "")

    @property
    def pid(self) -> Optional[str]:
        stdout, _ = remote.tempesta.run_cmd(
            "ps -eo pid,cmd | grep webshield | grep -v grep | awk '{print $1}' || true"
        )
        if not stdout:
            return None
        pids = [pid.decode() for pid in stdout.strip().split(b"\n") if pid]
        return pids[0] if pids else None

    @property
    def log(self) -> str:
        return self.read(self.log_path)

    def log_tail(self, n: int = 80) -> str:
        lines = self.log.splitlines()
        return "\n".join(lines[-n:])

    def hashes(self, config_path: Optional[str] = None) -> list[str]:
        """Lines WebShield wrote into the TFT/TFH include (``hash <id> 0 0;``)."""
        text = self.read(config_path or self.blocked_config)
        return [line for line in text.splitlines() if line.strip().startswith("hash")]

    def blocked_count(self, config_path: Optional[str] = None) -> int:
        return len(self.hashes(config_path))

    def is_blocked(self) -> bool:
        return bool(self.hashes()) or "Blocked user" in self.log

    def _started_timeout(self) -> float:
        if self.config.training_mode != TrainingMode.OFF:
            return self.training_duration_sec + 30
        return 30

    async def wait_until_started(self, timeout: Optional[float] = None) -> None:
        """Wait until both background monitors have started.

        Real training emits this only after TRAINING_MODE_DURATION_MIN.
        """
        timeout = self._started_timeout() if timeout is None else timeout
        ready = await util.wait_until(
            wait_cond=lambda: "Checked blocked users ready to release" not in self.log,
            timeout=timeout,
            abort_cond=lambda: not self.pid,
        )
        if not ready:
            raise RuntimeError(f"WebShield did not start monitoring.\n{self.log_tail()}")

    async def wait_until_tick(self, timeout: Optional[float] = None) -> None:
        """Wait for the next ``Checked risky users`` line (one detector slice)."""
        timeout = self.blocking_window + 5 if timeout is None else timeout
        n = self.log.count("Checked risky users")
        ready = await util.wait_until(
            wait_cond=lambda: self.log.count("Checked risky users") <= n,
            timeout=timeout,
            abort_cond=lambda: not self.pid,
        )
        if not ready:
            raise RuntimeError(f"WebShield tick did not fire.\n{self.log_tail()}")
