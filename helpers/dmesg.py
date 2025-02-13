"""Helper for Tempesta system log operations."""

from __future__ import print_function

import abc
import re
import typing
from contextlib import contextmanager
from typing import Callable, List

from . import error, remote, tf_cfg, util

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

from .access_log import AccessLogLine


# Collection of conditions for DmesgFinder.find
def amount_one(matches: List[str]) -> bool:
    return len(matches) == 1


def amount_zero(matches: List[str]) -> bool:
    return len(matches) == 0


def amount_positive(matches: List[str]) -> bool:
    return len(matches) > 0


def amount_equals(expected: int) -> Callable[[List[str]], bool]:
    return lambda matches: len(matches) == expected


def amount_greater_eq(expected: int) -> Callable[[List[str]], bool]:
    return lambda matches: len(matches) >= expected


class BaseTempestaLogger:

    @abc.abstractmethod
    def update(self):
        """
        Update logger data
        """

    @abc.abstractmethod
    def find(self, pattern: str, cond: typing.Callable = amount_one) -> bool:
        """
        Apply the condition to the parsed text with the provided regexp pattern
        """

    @abc.abstractmethod
    def log_findall(self, pattern: str):
        """
        Find all the text lines fitted with the regexp pattern
        """

    @abc.abstractmethod
    def show(self) -> None:
        """
        Prints the log data to the stdout
        """

    @abc.abstractmethod
    def access_log_records_count(self) -> int:
        """
        Count the number of access log records
        """

    @abc.abstractmethod
    def access_log_records_all(self) -> typing.List[AccessLogLine]:
        """
        Return all access log records
        """

    @abc.abstractmethod
    def access_log_last_message(self) -> AccessLogLine:
        """
        Return the last access log record
        """

    @abc.abstractmethod
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
        ja5t: str = None,
        ja5h: str = None,
        timestamp: int = None,
        dropped_events: int = None,
        response_time: int = None,
    ) -> typing.List[AccessLogLine]:
        """
        Find the log line with provided filters
        """


class DmesgFinder(BaseTempestaLogger):
    """dmesg helper class."""

    def __init__(self, disable_ratelimit=False):
        """
        Be careful using disable_ratelimit=True - you must be sure that GC frees the
        logger instance or delete the logger instance explicitly with `del`.
        Python GC can not to call destructor of the object at all on assertion
        or exception.
        """
        self.node = remote.tempesta
        self.log = ""
        self.start_time = float(self.node.run_cmd("date +%s.%N")[0])
        self.prev_message_cost = None

        # Suppress net ratelimiter to have all the messages in dmesg.
        if disable_ratelimit:
            self.prev_message_cost = int(
                self.node.run_cmd("sysctl --values net.core.message_cost")[0]
            )
            if self.prev_message_cost != 0:
                self.node.run_cmd("sysctl -w net.core.message_cost=0")

    def __del__(self):
        """
        Restore net.core.message_cost to not to flood the log on
        performance tests.

        Call it explicitly via del operator every time you don't need dmesg more.
        """
        if self.prev_message_cost is not None:
            self.node.run_cmd(f"sysctl -w net.core.message_cost={self.prev_message_cost}")

    def update(self):
        """Get log from the last run."""
        cmd = "journalctl -k -o cat --since=@{:.6f}".format(self.start_time)
        self.log, _ = self.node.run_cmd(cmd)

    def show(self):
        """Show tempesta system log."""
        print(self.log)

    def log_findall(self, pattern: str) -> list[str]:
        if isinstance(self.log, bytes):
            return re.findall(pattern, self.log.decode(errors="ignore"))

        return re.findall(pattern, self.log)

    def find(self, pattern: str, cond=amount_one) -> bool:
        """
        Why we need to put wait_until() logic under the hood:
        in most cases can be situation when dmesg isn't ready yet and we need to wait
        (leads to the bunch of annoying flacky tests). In all another cases
        log_findall() should be enough (in combination with len() or something).
        """
        tf_cfg.dbg(4, f"\tFinding pattern '{pattern}' in dmesg.")

        def wait_cond():
            self.update()
            matches = self.log_findall(pattern)
            return not cond(matches)

        return util.wait_until(wait_cond, timeout=2, poll_freq=0.2)

    def access_log_records_all(self) -> typing.List[AccessLogLine]:
        self.update()

        if isinstance(self.log, bytes):
            return AccessLogLine.parse_all(self.log.decode())

        return AccessLogLine.parse_all(self.log)

    def access_log_records_count(self) -> int:
        return len(self.access_log_records_all())

    def access_log_last_message(self) -> typing.Optional[AccessLogLine]:
        messages = self.access_log_records_all()

        if not messages:
            return None

        return messages[-1]

    @staticmethod
    def __records_filter(
        records: typing.List[AccessLogLine],
        address: str = None,
        vhost: str = None,
        method: str = None,
        uri: str = None,
        version: float = None,
        status: int = None,
        content_length: int = None,
        referer: str = None,
        user_agent: str = None,
        ja5t: str = None,
        ja5h: str = None,
        timestamp: int = None,
        dropped_events: int = None,
        response_time: int = None,
    ) -> typing.Generator[AccessLogLine, None, None]:
        for record in records:
            if address is not None and record.address != address:
                continue

            if vhost is not None and record.vhost != vhost:
                continue

            if method is not None and record.method != method:
                continue

            if uri is not None and record.uri != uri:
                continue

            if version is not None and record.version != version:
                continue

            if status is not None and record.status != status:
                continue

            if content_length is not None and record.response_content_length != content_length:
                continue

            if referer is not None and record.referer != referer:
                continue

            if user_agent is not None and record.user_agent != user_agent:
                continue

            if ja5t is not None and record.ja5t != ja5t:
                continue

            if ja5h is not None and record.ja5h != ja5h:
                continue

            if timestamp is not None and record.timestamp != timestamp:
                continue

            if dropped_events is not None and record.dropped_events != dropped_events:
                continue

            if response_time is not None and record.response_time != response_time:
                continue

            yield record

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
        ja5t: str = None,
        ja5h: str = None,
        timestamp: int = None,
        dropped_events: int = None,
        response_time: int = None,
    ) -> typing.List[AccessLogLine]:
        records = self.access_log_records_all()
        return [
            i
            for i in self.__records_filter(
                records,
                address=address,
                vhost=vhost,
                method=method,
                uri=uri,
                version=version,
                status=status,
                content_length=content_length,
                referer=referer,
                user_agent=user_agent,
                ja5t=ja5t,
                ja5h=ja5h,
                timestamp=timestamp,
                dropped_events=dropped_events,
                response_time=response_time,
            )
        ]


WARN_GENERIC = "Warning: "
WARN_SPLIT_ATTACK = "Warning: Paired request missing, HTTP Response Splitting attack?"
WARN_RATELIMIT = "net_ratelimit: [\d]+ callbacks suppressed"


@contextmanager
def wait_for_msg(pattern: str, strict=True):
    """Enter context: save start time for further dmesg grepping.
    Exit context: ensure that message occured.

    Strict parameter: raise error if message wasn't found,
    otherwise check if rate limit occured - this considered OK,
    otherwise write warning to the log.
    """

    dmesg = DmesgFinder(disable_ratelimit=strict)
    yield

    if dmesg.find(pattern):
        return

    if strict:
        raise error.Error("dmesg wait for message timeout")

    if not dmesg.find(WARN_RATELIMIT):
        # Ratelimiting messages appear only on next logging operation if
        # previous records were suppressed. This means that if some operation
        # produces a lot of logging and last log records are dropped, then we
        # learn it only with next log record, i.e. next operation.
        # The only good way to fix this is to properly setup system logger,
        # otherwise we either spend too much time on timeouts or observe
        # spurious exceptions.
        tf_cfg.dbg(2, f'No "{pattern}" log record and no ratelimiting')


def __change_dmesg_limit_on_tempesta_node(func, rate, *args, **kwargs):
    node = remote.tempesta
    cmd = "/proc/sys/net/core/message_cost"
    current_rate = node.run_cmd(f"cat {cmd}")[0].strip()
    try:
        node.run_cmd(f"echo {rate} > {cmd}")
        return func(*args, **kwargs)
    finally:
        node.run_cmd(f"echo {current_rate.decode()} > {cmd}")


def unlimited_rate_on_tempesta_node(func):
    """
    The decorator turns off dmesg messages rate limiting to ensure important
    messages are caught.
    """

    def func_wrapper(*args, **kwargs):
        return __change_dmesg_limit_on_tempesta_node(func, 0, *args, **kwargs)

    # we need to change name of function to work correctly with parametrize
    func_wrapper.__name__ = func.__name__
    return func_wrapper


def limited_rate_on_tempesta_node(func):
    """The decorator sets a dmesg messages rate limit."""

    def func_wrapper(*args, **kwargs):
        return __change_dmesg_limit_on_tempesta_node(func, 5, *args, **kwargs)

    # we need to change name of function to work correctly with parametrize
    func_wrapper.__name__ = func.__name__

    return func_wrapper
