import errno
import json

import run_config
from framework.helpers import remote
from framework.test_suite.tester import test_logger

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2026 Tempesta Technologies, Inc."
__license__ = "GPL2"


class DisabledListLoader(object):
    def __init__(self, disabled_list_file):
        self.disabled_list_file = disabled_list_file
        self.has_file = False
        self.disabled = []
        self.disable = False
        self.try_load()

    def try_load(self):
        """Try to load specified state file"""
        test_logger.info(f"Read disabled tests from '{self.disabled_list_file}'")
        try:
            self.disabled = []
            with open(self.disabled_list_file, "r") as dis_file:
                f = self.__parse_file(dis_file)
                self.disable = f["disable"]
                if self.disable:
                    self.disabled = f["disabled"]
                test_logger.info(
                    f"The number of disabled tests from '{self.disabled_list_file}' - "
                    f"{len(self.disabled)}"
                )
                return True
        except IOError as err:
            if err.errno != errno.ENOENT:
                raise Exception("Error loading disabled tests")
            else:
                test_logger.warning(f"File '{self.disabled_list_file}' not found")
        return False

    @staticmethod
    def __parse_file(dis_file):
        return json.load(dis_file)


def load_disabled() -> list[dict[str, str]]:
    disabled = []

    disabled_reader = DisabledListLoader("tests/tests_disabled.json")
    if disabled_reader.disable:
        disabled.extend(disabled_reader.disabled)

    if run_config.TCP_SEGMENTATION:
        r = DisabledListLoader("tests/tests_disabled_tcpseg.json")
        if r.disable:
            disabled.extend(r.disabled)

    if run_config.XFW_GATE_MODE_TESTS:
        r = DisabledListLoader("tests/tests_disabled_xfw_gate.json")
        if r.disable:
            disabled.extend(r.disabled)

    if run_config.XFW_HOST_MODE_TESTS:
        r = DisabledListLoader("tests/tests_disabled_xfw_host.json")
        if r.disable:
            disabled.extend(r.disabled)

    if isinstance(remote.tempesta, remote.RemoteNode):
        r = DisabledListLoader("tests/tests_disabled_remote.json")
        if r.disable:
            disabled.extend(r.disabled)

    if run_config.KERNEL_DBG_TESTS:
        r = DisabledListLoader("tests/tests_disabled_dbgkernel.json")
        if r.disable:
            disabled.extend(r.disabled)

    return disabled
