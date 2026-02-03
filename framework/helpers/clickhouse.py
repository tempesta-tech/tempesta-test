"""Simple client for Clickhouse access log storage"""

import re
import typing

import clickhouse_connect
from clickhouse_connect.driver import Client

from framework.helpers import dmesg, error, remote, tf_cfg
from framework.helpers.access_log import AccessLogLine

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

from framework.helpers.dmesg import amount_one

try:
    _connection: Client = clickhouse_connect.get_client(
        host=tf_cfg.cfg.get("TFW_Logger", "ip"),
        port=int(tf_cfg.cfg.get("TFW_Logger", "clickhouse_http_port")),
        database=tf_cfg.cfg.get("TFW_Logger", "clickhouse_database"),
        username=tf_cfg.cfg.get("TFW_Logger", "clickhouse_username"),
        password=tf_cfg.cfg.get("TFW_Logger", "clickhouse_password"),
    )
except clickhouse_connect.driver.exceptions.OperationalError as e:
    raise error.ClickhouseNotAvailable() from None


class ClickHouseFinder(dmesg.BaseTempestaLogger):
    http_methods = {
        "COPY": 1,
        "DELETE": 2,
        "GET": 3,
        "HEAD": 4,
        "LOCK": 5,
        "MKCOL": 6,
        "MOVE": 7,
        "OPTIONS": 8,
        "PATCH": 9,
        "POST": 10,
        "PROPFIND": 11,
        "PROPPATCH": 12,
        "PUT": 13,
        "TRACE": 14,
        "UNLOCK": 15,
        "PURGE": 16,
    }

    def __init__(self):
        self.__log_data: str = ""
        self.__table: str = tf_cfg.cfg.get("TFW_Logger", "clickhouse_table")
        self.__log_path: str = tf_cfg.cfg.get("TFW_Logger", "log_path")

    @staticmethod
    def __build_log_line(db_record) -> AccessLogLine:
        return AccessLogLine(
            timestamp=db_record[0],
            address=db_record[1],
            method=db_record[2],
            version=db_record[3],
            status=db_record[4],
            response_content_length=db_record[5],
            response_time=db_record[6],
            vhost=db_record[7],
            uri=db_record[8],
            referer=db_record[9],
            user_agent=db_record[10],
            tft=db_record[11],
            tfh=db_record[12],
            dropped_events=db_record[13],
        )

    def update(self) -> None:
        """
        Read data of tfw_logger daemon file
        """
        stdout, _ = remote.tempesta.run_cmd(f"cat {self.__log_path}")
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
        if self.access_log_table_exists():
            _connection.command(f"delete from {self.__table} where true")

    def access_log_records_count(self) -> int:
        """
        Count all the log records
        """
        try:
            res = _connection.query(f"select count(1) from {self.__table}")
            return res.result_rows[0][0]
        except clickhouse_connect.driver.exceptions.DatabaseError as e:
            assert "Unknown table" in str(e)
            return 0

    def access_log_records_all(self) -> typing.List[AccessLogLine]:
        """
        Read all the log records
        """
        results = _connection.query(
            f"""
            select * 
            from {self.__table}
            order by timestamp desc
            """,
        )
        return list(
            map(
                lambda x: self.__build_log_line(x),
                results.result_rows,
            )
        )

    def access_log_last_message(self) -> typing.Optional[AccessLogLine]:
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
        return _connection.command(f"exists table {self.__table}") == 1

    def access_log_find(
        self,
        address: str = None,
        vhost: str = None,
        method: str = None,
        uri: str = None,
        version: float = None,
        status: int = None,
        content_length: int = None,
        referer: str = None,
        user_agent: str = None,
        tft: str = None,
        tfh: str = None,
        timestamp: int = None,
        dropped_events: int = None,
        response_time: int = None,
    ) -> typing.List[AccessLogLine]:
        method_id = self.http_methods.get(method)

        if not method_id:
            raise ValueError(f"Method '{method}' not found")

        results = _connection.query(
            f"""
            SELECT *
            from {self.__table}
            WHERE
                    (if(%(address)s is not null, address = %(address)s, 1))
                and (if(%(vhost)s is not null, vhost = %(vhost)s, 1))
                and (if(%(method)s is not null, method = %(method)s, 1))
                and (if(%(uri)s is not null, uri = %(uri)s, 1))
                and (if(%(version)s is not null, version = %(version)s, 1))
                and (if(%(status)s is not null, status = %(status)s, 1))
                and (if(%(content_length)s is not null, response_content_length = %(content_length)s, 1))
                and (if(%(referer)s is not null, referer = %(referer)s, 1))
                and (if(%(user_agent)s is not null, user_agent = %(user_agent)s, 1))
                and (if(%(tft)s is not null, tft = %(tft)s, 1))
                and (if(%(tfh)s is not null, tfh = %(tfh)s, 1))
                and (if(%(timestamp)s is not null, timestamp = %(timestamp)s, 1))
                and (if(%(dropped_events)s is not null, dropped_events = %(dropped_events)s, 1))
                and (if(%(response_time)s is not null, response_time = %(response_time)s, 1))
            """,
            parameters={
                "address": address,
                "vhost": vhost,
                "method": method_id,
                "uri": uri,
                "version": version,
                "status": status,
                "content_length": content_length,
                "referer": referer,
                "user_agent": user_agent,
                "tft": tft,
                "tfh": tfh,
                "timestamp": timestamp,
                "dropped_events": dropped_events,
                "response_time": response_time,
            },
        )
        return list(
            map(
                lambda x: self.__build_log_line(x),
                results.result_rows,
            )
        )

    def drop_access_log_table(self) -> str:
        """
        Drop the access log table if exists to clear the logs and
        prevent an errors while tests work with the different
        table schemas
        """
        return _connection.command(f"drop table if exists {self.__table}")
