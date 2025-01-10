"""Simple client for Clickhouse access log storage"""

import dataclasses
import typing
from datetime import datetime
from ipaddress import IPv4Address

import clickhouse_connect

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


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


class ClickHouseLogStorageClient:
    def __init__(
        self,
        host: str = None,
        username: str = None,
        password: str = None,
        port: int = None,
        dsn: str = None,
    ):
        self.clickhouse_client = clickhouse_connect.get_client(
            host=host,
            username=username,
            password=password,
            port=port,
            dsn=dsn,
        )

    def log_table_exists(self) -> bool:
        result = self.clickhouse_client.command("exists table access_log")
        return result == 1

    def delete_all(self) -> None:
        self.clickhouse_client.command("delete from access_log where true")

    def total_count(self) -> int:
        res = self.clickhouse_client.query("select count(1) from access_log")
        return res.result_rows[0][0]

    def read(self) -> typing.List[ClickHouseLogRecord]:
        results = self.clickhouse_client.query(
            """
            select * 
            from access_log
            order by timestamp desc
            """,
        )
        return list(map(lambda x: ClickHouseLogRecord(*x), results.result_rows))
