__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2026 Tempesta Technologies, Inc."
__license__ = "GPL2"

from typing import Optional

import pytest
from _pytest.config import Config, argparsing
from _pytest.runner import runtestprotocol

import run_config
from framework.helpers import memworker, remote, tf_cfg
from framework.test_suite import prepare
from framework.test_suite import pytest_support as ps
from framework.test_suite import tester
from framework.test_suite.tester import test_logger


def pytest_addoption(parser: argparsing.Parser) -> None:
    group = parser.getgroup("tempesta")

    group.addoption(
        "-R",
        "--repeat",
        action="store",
        type=int,
        default=1,
        metavar="N",
        help="Repeat every selected test N times",
    )
    group.addoption(
        "--save-config",
        action="store",
        default=None,
        choices=["local", "remote"],
        metavar="{local,remote}",
        help="Save default configuration to config file and exit",
    )
    group.addoption(
        "-I",
        "--identifier",
        action="store",
        default=None,
        help="Path to tcpdump results folder",
    )
    group.addoption(
        "--save-tcpdump",
        action="store_true",
        default=False,
        help="Enable tcpdump per test (replaces -s)",
    )
    group.addoption(
        "-S",
        "--save-secrets",
        action="store_true",
        default=False,
        help="Save TLS secrets to secrets.txt (replaces -S)",
    )
    group.addoption(
        "-T",
        "--tcp-segmentation",
        action="store",
        type=int,
        default=0,
        help="Run all tests with TCP segmentation",
    )
    group.addoption(
        "--kernel-dbg",
        action="store_true",
        default=False,
        help="Run tests for the kernel with sanitizers/checkers",
    )
    group.addoption(
        "-M",
        "--check-memory-leaks",
        action="store_true",
        default=False,
        help="Check memory leaks for each test",
    )
    group.addoption(
        "--dont-prepare",
        action="store_true",
        default=False,
        help="Skip TCP preparation step",
    )
    group.addoption(
        "-Z",
        "--run-disabled",
        action="store_true",
        default=False,
        help="Run only tests from the disabled lists",
    )
    group.addoption(
        "-P",
        "--disable-auto-parser",
        action="store_true",
        default=False,
        help="Disable HTTP auto-parser",
    )
    group.addoption(
        "-D",
        "--debug-files",
        action="store_true",
        default=False,
        help="Don't remove generated config files",
    )
    group.addoption(
        "-E",
        "--tempesta-retry",
        action="store_true",
        default=False,
        help="Retry failed tests listed in tests/tests_retry",
    )


@pytest.hookimpl(tryfirst=True)
def pytest_cmdline_main(config: Config) -> Optional[int]:
    save_config: Optional[str] = config.getoption("--save-config")
    if save_config:
        tf_cfg.cfg.save_defaults(save_config)
        return 0
    return None


def pytest_configure(config: Config) -> None:
    if config.getoption("--identifier"):
        tester.build_path = config.getoption("--identifier")

    if config.getoption("--save-tcpdump"):
        tester.save_tcpdump = True
        run_config.SAVE_SECRETS = True

    if config.getoption("--save-secrets"):
        run_config.SAVE_SECRETS = True

    if config.getoption("--tcp-segmentation") > 0:
        run_config.TCP_SEGMENTATION = config.getoption("--tcp-segmentation")

    if config.getoption("--kernel-dbg"):
        run_config.KERNEL_DBG_TESTS = True

    if config.getoption("--check-memory-leaks"):
        run_config.CHECK_MEMORY_LEAKS = True

    if config.getoption("--disable-auto-parser"):
        run_config.AUTO_PARSER = False

    if config.getoption("--debug-files"):
        remote.DEBUG_FILES = True

    # --- tf_cfg init ---
    tf_cfg.cfg.check()
    tf_cfg.cfg.configure_logger()

    # --- root check ---
    ps.ensure_root()

    # --- register markers used by --tempesta-retry ---
    config.addinivalue_line("markers", "flaky(reruns): rerun test up to `reruns` times")


def pytest_collection_modifyitems(config: Config, items: list[pytest.Item]) -> None:
    ps.handle_disabled_tests(config, items)
    if not items:
        return

    ps.apply_test_priorities(items)
    ps.apply_retry_markers(config, items)


def pytest_sessionfinish(session: pytest.Session, exitstatus: int | pytest.ExitCode) -> None:
    tf_cfg.cfg.log_listener.stop()


def pytest_runtest_protocol(item: pytest.Item, nextitem: Optional[pytest.Item]) -> Optional[bool]:
    count: int = item.config.getoption("--repeat")
    if count <= 1:
        return None

    for _ in range(count):
        runtestprotocol(item, nextitem=nextitem, log=True)

    return True


@pytest.fixture(scope="session")
def _configure_tcp(pytestconfig: Config) -> None:
    """allows run tests from docker container."""
    if not pytestconfig.getoption("--dont-prepare"):
        prepare.configure_tcp()
    yield


@pytest.fixture(scope="session")
def _manage_kernel_debug_session(_configure_tcp: None) -> None:
    if run_config.KERNEL_DBG_TESTS:
        ps.check_kmemleak_availability()
        remote.tempesta.run_cmd("echo clear > /sys/kernel/debug/kmemleak")
    yield
    if run_config.KERNEL_DBG_TESTS:
        ps.check_kmemleak()


@pytest.fixture(scope="session")
def _tempesta_session_memory_check(_manage_kernel_debug_session: None) -> None:
    """Whole-suite memory-leak check."""
    with memworker.check_memory_leaks():
        yield


@pytest.fixture(scope="function", autouse=True)
def _log_test_lifecycle(request: pytest.FixtureRequest) -> None:
    """Per-test logging: start/stop + dmesg."""
    nodeid: str = request.node.nodeid

    test_logger.info(f"\n\n{'-' * 100}\nStart test '{nodeid}'\n{'-' * 100}")
    tf_cfg.log_dmesg(remote.tempesta, f"Start test: {nodeid}")

    yield

    tf_cfg.log_dmesg(remote.tempesta, f"End test:   {nodeid}")
    test_logger.info(f"\n\n{'-' * 100}\nEnd test '{nodeid}'\n{'-' * 100}")
