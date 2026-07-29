__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2026 Tempesta Technologies, Inc."
__license__ = "GPL2"


import os
import resource
from pathlib import Path

import pytest

from framework.helpers import error, remote
from framework.helpers.tf_cfg import test_logger
from framework.test_suite import shell


def _matches_any_nodeid(nodeid: str, prefixes: list[str]) -> bool:
    """
    Match a pytest nodeid directly against prefixes that are already in
    pytest nodeid style. A prefix can point at:
      - a directory or module path:  "tests/tls" or "tests/tls/test_x.py"
      - a class or method within a module: "tests/tls/test_x.py::Cls"
                                            "tests/tls/test_x.py::Cls::method"
    so a match requires the boundary right after the prefix to be either
    "/" (path) or "::" (class/method), or an exact match.
    Used for tests_disabled.json, tests_priority, and tests_retry.
    """
    for prefix in prefixes:
        prefix = prefix.strip()
        if not prefix:
            continue

        if nodeid == prefix or nodeid.startswith((f"{prefix}/", f"{prefix}::")):
            return True
    return False


def _run_disabled_tests(
    disabled: list[dict[str, str]], disabled_names: list[str], items: list[pytest.Item]
) -> None:
    if not disabled_names:
        test_logger.critical("No disabled tests, exiting")
        items[:] = []
        return

    items[:] = [i for i in items if _matches_any_nodeid(i.nodeid, disabled_names)]
    for d in disabled:
        test_logger.info(f'Run disabled test "{d["name"]}" : {d["reason"]}')


def ensure_root() -> None:
    if os.geteuid() != 0:
        raise pytest.UsageError("Please, run tests as root.")
    nofile = 1048576
    resource.setrlimit(resource.RLIMIT_NOFILE, (nofile, nofile))


def check_kmemleak_availability() -> None:
    try:
        remote.tempesta.run_cmd("cat /sys/kernel/debug/kmemleak")
    except error.ProcessBadExitStatusException as e:
        msg = "kmemleak is possibly disabled. Please enable kmemleak or do not use `--kernel-dbg` option."
        test_logger.critical(msg)
        raise error.KmemLeakException(msg) from e


def check_kmemleak() -> None:
    from framework.services import tempesta

    tfw = tempesta.Tempesta(vhost_auto=False)
    tfw.config.set_defconfig("")
    tfw.check_config = False
    tfw.start()

    try:
        remote.tempesta.run_cmd("echo scan > /sys/kernel/debug/kmemleak", timeout=60)
        stdout, stderr = remote.tempesta.run_cmd("cat /sys/kernel/debug/kmemleak", timeout=60)
        kmemleak_msg = (
            (
                "kmemleak result.\n"
                "----------------------------------------------------------------------------\n"
                f"{stdout.decode()}\n"
                "----------------------------------------------------------------------------\n"
            )
            if stdout
            else "/sys/kernel/debug/kmemleak is empty"
        )
        test_logger.critical(kmemleak_msg)
        if b"tfw_" in stdout:
            raise error.KmemLeakException(stdout=stdout.decode())
    finally:
        tfw.stop()


def handle_disabled_tests(config: pytest.Config, items: list[pytest.Item]) -> None:
    """disabled / run-disabled (-Z)."""
    disabled = shell.load_disabled()
    disabled_names = [d["name"] for d in disabled]

    if config.getoption("--run-disabled"):
        _run_disabled_tests(disabled, disabled_names, items)
        return

    if disabled_names:
        for d in disabled:
            test_logger.debug(f'Disabled test name" : {d["reason"]}')
        items[:] = [i for i in items if not _matches_any_nodeid(i.nodeid, disabled_names)]


def apply_test_priorities(items: list[pytest.Item]) -> None:
    """priority (tests/tests_priority)."""
    priority_file = Path("tests") / "tests_priority"
    if not priority_file.is_file():
        return

    with open(priority_file) as f:
        priorities = [l.rstrip() for l in f if l.strip()]
    priorities.reverse()

    def _prio_key(item):
        for idx, p in enumerate(priorities):
            if _matches_any_nodeid(item.nodeid, [p]):
                return idx
        return len(priorities)

    items.sort(key=_prio_key)


def apply_retry_markers(config: pytest.Config, items: list[pytest.Item]) -> None:
    """retry (--tempesta-retry, tests/tests_retry)"""
    if not config.getoption("--tempesta-retry"):
        return

    retry_file = Path("tests") / "tests_retry"
    if not retry_file.is_file():
        return

    with open(retry_file) as f:
        retry_prefixes = [l.rstrip() for l in f if l.strip()]

    for item in items:
        if _matches_any_nodeid(item.nodeid, retry_prefixes):
            item.add_marker(pytest.mark.flaky(reruns=3))
