"""Helpers to memory consumptions in tests."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2025-2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

import gc
import time
import typing
import unittest
from contextlib import contextmanager
from dataclasses import dataclass

import psutil

from framework.helpers import error, remote, tf_cfg
from framework.helpers.tf_cfg import test_logger

_STEPS_TO_CHECK_MEMORY = 5
_SLEEP_TO_CHECK_MEMORY = 1


class _MemoryStats:
    def __init__(self, system_memory_first: int, python_memory_first: typing.Optional[int]):
        self._system_memory_first: int = system_memory_first
        self._python_memory_first: typing.Optional[int] = python_memory_first
        self._system_memory_second: typing.Optional[int] = None
        self._python_memory_second: typing.Optional[int] = None
        self._delta_python: int = 0
        self._memory_leak_threshold: int = int(tf_cfg.cfg.get("General", "memory_leak_threshold"))
        self._memory_consumption: typing.Optional[int] = None

    @property
    def memory_consumption(self) -> int:
        return self._memory_consumption

    def set_second_memory_stats(
        self, system_memory_second: int, python_memory_second: typing.Optional[int]
    ) -> None:
        self._system_memory_second = system_memory_second
        self._python_memory_second = python_memory_second

        if self._python_memory_first is not None and self._python_memory_second is not None:
            self._delta_python = self._python_memory_second - self._python_memory_first
        self._memory_consumption = (
            self._system_memory_second - self._delta_python - self._system_memory_first
        )

    def is_memory_leak(self) -> bool:
        if self._system_memory_second is None:
            raise ValueError("The method require to call 'set_second_memory_stats' before.")
        return self._memory_consumption > self._memory_leak_threshold

    def __str__(self):
        msg = (
            f"Before: system memory: {self._system_memory_first} KB;\n"
            f"After: system memory: {self._system_memory_second} KB;\n"
            f"Memory consumption: {self._memory_consumption} KB\n"
        )
        if self._python_memory_first is not None:
            msg = (
                f"Before: python memory: {self._python_memory_first} KB;\n"
                f"After: python memory: {self._python_memory_second} KB;\n"
                f"Delta python: {self._delta_python} KB\n"
            ) + msg
        return msg


@dataclass
class _FailTest:
    test: unittest.TestCase
    mem_stats: _MemoryStats


class MemoryChecker:
    _fail_tests: list[_FailTest] = []
    _is_local_setup: bool = isinstance(remote.tempesta, remote.LocalNode)
    _node: remote.ANode = remote.tempesta

    @classmethod
    def _add_fail_test(cls, test: _FailTest) -> None:
        cls._fail_tests.append(test)

    def _get_used_memory(self) -> int:
        """Get used system memory in KB."""
        stdout, _ = self._node.run_cmd("free")
        return int(stdout.decode().split("\n")[1].split()[2])

    def _get_used_python_memory(self) -> int | None:
        """Get used python memory in KB for host (clients\severs)."""
        return psutil.Process().memory_info().rss // 1024 if self._is_local_setup else None

    def set_second_memory_stats(self, mem_stats: _MemoryStats) -> None:
        """
        Set second memory stats.
        It checks memory consumption in cycle because memory statistics can be unstable
        and we need to make sure that the memory is not being released.
        """
        mem_stats.set_second_memory_stats(
            system_memory_second=self._get_used_memory(),
            python_memory_second=self._get_used_python_memory(),
        )

        for _ in range(_STEPS_TO_CHECK_MEMORY):
            if self._is_local_setup:
                gc.collect()
            if mem_stats.is_memory_leak():
                time.sleep(_SLEEP_TO_CHECK_MEMORY)
            else:
                break
            mem_stats.set_second_memory_stats(
                system_memory_second=self._get_used_memory(),
                python_memory_second=self._get_used_python_memory(),
            )

    def get_first_memory_stats(self) -> _MemoryStats:
        return _MemoryStats(
            system_memory_first=self._get_used_memory(),
            python_memory_first=self._get_used_python_memory(),
        )

    def check_memory_consumption_of_test(
        self, mem_stats: _MemoryStats, test: unittest.TestCase
    ) -> None:
        """
        Add the test to the failed list when memory consumption is detected.
        Don't raise exceptions.
        """
        self.set_second_memory_stats(mem_stats)
        test_logger.info(f"Check memory leaks for {test.id()}:\n{mem_stats}")
        if mem_stats.is_memory_leak():
            self._fail_tests.append(_FailTest(test, mem_stats))

    def check_memory_consumption_of_test_suite(self, mem_stats: _MemoryStats) -> None:
        """
        Check memory leaks for test suite and raise MemoryConsumptionException when memory consumption is detected.
        """
        self.set_second_memory_stats(mem_stats)
        if self._fail_tests and mem_stats.is_memory_leak():
            raise error.MemoryConsumptionException(
                f"The memory leaks for test suite:\n{mem_stats}\n"
                "The tests with unexpected memory consumption:\n"
                + f"\n".join(
                    [
                        f"{fail.test.id()}: {fail.mem_stats.memory_consumption} KB;"
                        for fail in self._fail_tests
                    ]
                )
            )

        test_logger.critical(
            "\n----------------------------------------------------------------------------\n"
            f"Check memory leaks for test suite:\n{mem_stats}"
            "----------------------------------------------------------------------------"
        )


@contextmanager
def check_memory_consumptions(test: unittest.TestCase) -> None:
    """
    The context manager to check a memory consumption on Tempesta FW node.
    It adds test to fail list in MemoryChecker when memory consumption
    is greater than memory leak threshold
    """
    memory_worker = MemoryChecker()
    mem_stats = memory_worker.get_first_memory_stats()
    yield
    memory_worker.check_memory_consumption_of_test(mem_stats, test)


@contextmanager
def check_memory_leaks() -> None:
    """
    The context manager to check memory leaks on Tempesta FW node the test suite.
    """
    memory_worker = MemoryChecker()
    mem_stats = memory_worker.get_first_memory_stats()
    yield
    memory_worker.check_memory_consumption_of_test_suite(mem_stats)
