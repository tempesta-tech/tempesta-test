from __future__ import print_function

import sys  # for sys.exc_info
from dataclasses import dataclass

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017 Tempesta Technologies, Inc."
__license__ = "GPL2"


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


@dataclass
class TestConditionsAreNotCompleted(Error):
    test_name: str = None
    attempt: int = None

    def __str__(self):
        return (
            f"The conditions for '{self.test_name}' are not completed. "
            f"Attempts - {self.attempt}"
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
