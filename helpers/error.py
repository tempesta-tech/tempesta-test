__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 202-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import sys
from dataclasses import dataclass
from typing import Any, Optional, Union

from helpers import tf_cfg


class Error(Exception):
    """Base exception class for unrecoverable framework errors.

    Python unittest treats AssertionError as test failure rather than the error.
    Separate exception class is needed to indicate that error happen and
    test framework is not working as expected.
    """

    pass


@dataclass
class MemoryConsumptionException(Error):
    msg: str
    delta_used_memory: int
    memory_leak_threshold: int

    def __str__(self):
        return (
            f"\n{self.msg}"
            f"\nUsed memory >= memory_leak_threshold "
            f"({self.delta_used_memory} KB >= {self.memory_leak_threshold} KB)"
        )


@dataclass
class KmemLeakException(Error):
    stdout: str

    def __str__(self):
        return f"kmemleak found 'tfw' in /sys/kernel/debug/kmemleak:\n{self.stdout}"


@dataclass
class ServiceStoppingException(Error):
    exceptions: dict

    def __str__(self):
        return f"".join(
            [
                "\n---------------------------------------------------------\n"
                f"Exception in stopping process for {service}: {exception}\n"
                "---------------------------------------------------------\n"
                for service, exception in self.exceptions.items()
            ]
        )


class ClickhouseNotAvailable(Exception):
    """When clickhouse is not started or access is incorrect."""

    def __str__(self):
        return (
            "You must run Clickhouse server on the "
            + f"{tf_cfg.cfg.get('TFW_Logger', 'ip')}:"
            + f"{tf_cfg.cfg.get('TFW_Logger', 'clickhouse_http_port')} "
            + "node before run the tests."
        )


class KmemleakException(Exception):
    """If error with `kmemleak` processing."""

    def __init__(self, message: str = None):
        """
        Init class instance.

        Args:
            message (str): exception message
        """
        base_msg = f"""
Msg: {message}

If you received a message such `/sys/kernel/debug/kmemleak: No such file or directory`,
it indicates, that kmemleak is 100% disabled.

Check for some extra info: https://docs.kernel.org/dev-tools/kmemleak.html .
        """
        super().__init__(base_msg)


class BaseCmdException(Exception):
    """Base class to cmd-like exceptions,"""

    def __init__(
        self,
        message: Any = None,
        stdout: Union[str, bytes] = "",
        stderr: Union[str, bytes] = "",
        rt: Optional[int] = None,
    ):
        """
        Init class instance.

        Args:
            message (Any): exception message
            stdout (Union[str, bytes]): stdout of a process value when an exception is raised
            stderr (Union[str, bytes]): stderr of a process value when an exception is raised
            rt (Optional[int]): return code of a process when an exception is raised
        """
        super().__init__(str(message))
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = rt


class ProcessBadExitStatusException(BaseCmdException):
    """If exit status of a process is bad (not expected). Usually, 0(zero) is considered as good exit status."""


class ProcessKilledException(BaseCmdException):
    """If a process was not able to stop gracefully and was killed."""


class CommandExecutionException(BaseCmdException):
    """If something happened during a command execution."""


@dataclass
class TestConditionsAreNotCompleted(Error):
    test_name: str
    attempts: Optional[int] = None

    def __str__(self):
        return f"The conditions for '{self.test_name}' are not completed." + (
            f" Attempts - {self.attempts}" if self.attempts else ""
        )


def assertFalse(expression, msg=""):
    """Raise test framework error if 'expression' is true."""
    if expression:
        raise Error(msg)


def assertTrue(expression, msg=""):
    """Raise test framework error if 'expression' is false."""
    if not expression:
        raise Error(msg)


def bug(msg="", stdout=None, stderr=None):
    """Raise test framework error."""
    exc_info = sys.exc_info()
    if exc_info[1] is not None:
        msg += " (%s: %s)" % (exc_info[0].__name__, exc_info[1])
    if stdout:
        stdout = "\n\t" + "\n\t".join(stdout.decode().splitlines()) + "\n"
        msg += "\nstdout:%s" % stdout
    if stderr:
        stderr = "\n\t" + "\n\t".join(stderr.decode().splitlines()) + "\n"
        msg += "\nstderr:%s" % stderr
    raise Error(msg).with_traceback(exc_info[2])


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
