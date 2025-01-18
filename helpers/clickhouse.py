"""Simple client for Clickhouse access log storage"""

import dataclasses
import time
import typing
from datetime import datetime
from ipaddress import IPv4Address

import clickhouse_connect

from helpers import control, remote

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

from test_suite.prepare import configure


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
    dropped_events: int


class ClickHouseFinder:
    def __init__(
        self,
        host: str = None,
        username: str = None,
        password: str = None,
        port: int = None,
        database: str = None,
        daemon_log: str = None,
    ):
        self.daemon_log: str = daemon_log
        self.node = remote.tempesta
        self.start_time = float(self.node.run_cmd("date +%s.%N")[0])
        self._clickhouse_client = clickhouse_connect.get_client(
            host=host,
            username=username,
            password=password,
            port=port,
            database=database,
        )

    def log_table_exists(self) -> bool:
        """
        Check if table already created
        """
        result = self._clickhouse_client.command("exists table access_log")
        return result == 1

    def delete_all(self) -> None:
        """
        Delete all log records
        """
        self._clickhouse_client.command("delete from access_log where true")

    def total_count(self) -> int:
        """
        Count all the log records
        """
        res = self._clickhouse_client.query("select count(1) from access_log")
        return res.result_rows[0][0]

    def read(self) -> typing.List[ClickHouseLogRecord]:
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

    def last_message(self) -> ClickHouseLogRecord:
        """
        Read the data of tfw_logger daemon file
        """
        return self.read()[0]

    def tfw_log_file_get_data(self, tempesta_instance: control.Tempesta) -> str:
        """
        Read data of tfw_logger daemon file
        """
        stdout, _ = tempesta_instance.node.run_cmd(f"cat {self.daemon_log}")
        return stdout.decode()

    def tfw_log_file_remove(self, tempesta_instance: control.Tempesta) -> None:
        """
        Remove tfw logger file
        """
        stdout, stderr = tempesta_instance.node.run_cmd(f"rm -f {self.daemon_log}")
        assert (stdout, stderr) == (b"", b"")

    def tfw_log_file_exists(self, tempesta_instance: control.Tempesta) -> bool:
        """
        Check if tfw log file exists
        """
        stdout, stderr = tempesta_instance.node.run_cmd(f"ls -la {self.daemon_log} | wc -l")
        return (stdout, stderr) == (b"1\n", b"")

    def tfw_logger_signal(
        self, tempesta_instance: control.Tempesta, signal: typing.Literal["STOP", "CONT"]
    ) -> None:
        tempesta_instance.node.run_cmd(f"kill -{signal} $(pidof tfw_logger)")

    def wait_until_tfw_logger_start(
        self, tempesta_instance: control.Tempesta, timeout: int = 5, raise_error: bool = True
    ) -> None:
        """
        Block thread until tfw_logger starts
        """
        total_time_exceed = 0

        while total_time_exceed < timeout:
            time.sleep(0.1)
            total_time_exceed += 0.1

            if not self.tfw_log_file_exists(tempesta_instance):
                continue

            stdout = self.tfw_log_file_get_data(tempesta_instance)

            if stdout.endswith("Daemon started\n"):
                return

        if not raise_error:
            return

        raise FileNotFoundError(
            f'TFW logger daemon log file (path="{self.daemon_log}") was not found'
        )
