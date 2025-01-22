"""Simple client for Clickhouse access log storage"""

import dataclasses
import re
import time
import typing
from datetime import datetime
from ipaddress import IPv4Address

import clickhouse_connect

from helpers import dmesg, remote, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

from helpers.dmesg import amount_one


@dataclasses.dataclass
class ClickHouseLogRecord:
    timestamp: datetime
    address: IPv4Address
    method: int
    version: int
    status: int
    response_content_length: int
    response_time: int
    vhost: str
    uri: str
    referer: str
    user_agent: str
    ja5t: int
    ja5h: int
    dropped_events: int


class ClickHouseFinder(dmesg.BaseTempestaLogger):
    def __init__(self):
        self.raise_error_on_logger_file_missing: bool = True
        self.daemon_log: str = tf_cfg.cfg.get("TFW_Logger", "daemon_log")
        self.node = remote.tempesta
        self.start_time = float(self.node.run_cmd("date +%s.%N")[0])
        self._clickhouse_client = clickhouse_connect.get_client(
            host=tf_cfg.cfg.get("TFW_Logger", "clickhouse_host"),
            port=int(tf_cfg.cfg.get("TFW_Logger", "clickhouse_port")),
            username=tf_cfg.cfg.get("TFW_Logger", "clickhouse_username"),
            password=tf_cfg.cfg.get("TFW_Logger", "clickhouse_password"),
            database=tf_cfg.cfg.get("TFW_Logger", "clickhouse_database"),
        )
        self.__log_data: str = ""

    def update(self) -> None:
        """
        Read data of tfw_logger daemon file
        """
        stdout, _ = self.node.run_cmd(f"cat {self.daemon_log}")
        self.__log_data = stdout.decode()

    def log_findall(self, pattern: str):
        return re.findall(pattern, self.__log_data, flags=re.MULTILINE | re.DOTALL)

    def find(self, pattern: str, cond: typing.Callable = amount_one) -> bool:
        self.update()
        lines = self.log_findall(pattern)
        return cond(lines)

    def show(self) -> None:
        print(self.__log_data)

    def access_log_clear(self) -> None:
        """
        Delete all log records
        """
        self._clickhouse_client.command("delete from access_log where true")

    def access_log_records_count(self) -> int:
        """
        Count all the log records
        """
        res = self._clickhouse_client.query("select count(1) from access_log")
        return res.result_rows[0][0]

    def access_log_records_all(self) -> typing.List[ClickHouseLogRecord]:
        """
        Read all the log records
        """
        results = self._clickhouse_client.query(
            """
            select * 
            from access_log
            order by timestamp desc
            """,
        )
        return list(map(lambda x: ClickHouseLogRecord(*x), results.result_rows))

    def access_log_last_message(self) -> typing.Optional[ClickHouseLogRecord]:
        """
        Read the data of tfw_logger daemon file
        """
        records = self.access_log_records_all()

        if not records:
            return None

        return records[-1]

    def access_log_table_exists(self) -> bool:
        """
        Check if table already created
        """
        result = self._clickhouse_client.command("exists table access_log")
        return result == 1

    def tfw_log_file_remove(self) -> None:
        """
        Remove tfw logger file
        """
        stdout, stderr = self.node.run_cmd(f"rm -f {self.daemon_log}")
        assert (stdout, stderr) == (b"", b"")

    def tfw_log_file_exists(self) -> bool:
        """
        Check if tfw log file exists
        """
        stdout, stderr = self.node.run_cmd(f"ls -la {self.daemon_log} | wc -l")
        return (stdout, stderr) == (b"1\n", b"")

    def tfw_logger_signal(self, signal: typing.Literal["STOP", "CONT"]) -> None:
        self.node.run_cmd(f"kill -{signal} $(pidof tfw_logger)")

    def tfw_logger_wait_until_ready(self, timeout: int = 5) -> None:
        """
        Block thread until tfw_logger starts
        """
        total_time_exceed = 0

        while total_time_exceed < timeout:
            time.sleep(0.1)
            total_time_exceed += 0.1

            if not self.tfw_log_file_exists():
                continue

            if self.find("Daemon started\n"):
                return

        if not self.raise_error_on_logger_file_missing:
            return

        raise FileNotFoundError(
            f'TFW logger daemon log file (path="{self.daemon_log}") was not found'
        )
