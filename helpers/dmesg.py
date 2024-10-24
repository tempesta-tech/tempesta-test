"""Helper for Tempesta system log operations."""

from __future__ import print_function

import re
from contextlib import contextmanager
from typing import Callable, List

from . import error, remote, tf_cfg, util

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2018-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"


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


class DmesgFinder(object):
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

    def log_findall(self, pattern: str):
        return re.findall(pattern, self.log.decode(errors="ignore"))

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
