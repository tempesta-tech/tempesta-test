"""Tests for client mem configuration."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

from helpers import error
from test_suite import marks, tester


class TestConfig(tester.TempestaTest):
    """
    This class contains tests for 'client_mem' directives.
    """

    tempesta = {
        "config": """
listen 80;
"""
    }

    def __update_tempesta_config(self, client_mem_config: str):
        new_config = self.get_tempesta().config.defconfig
        self.get_tempesta().config.defconfig = new_config + client_mem_config

    @marks.Parameterize.expand(
        [
            marks.Param(name="not_present", client_mem_config="client_mem;\n"),
            marks.Param(name="to_many_args", client_mem_config="client_mem 1 3 5;\n"),
            marks.Param(name="no_attrs", client_mem_config="client_mem 1 b=3;\n"),
            marks.Param(name="value_1", client_mem_config="client_mem 11aa;\n"),
        ]
    )
    def test_invalid(self, name, client_mem_config):
        tempesta = self.get_tempesta()
        self.__update_tempesta_config(client_mem_config)
        self.oops_ignore = ["ERROR"]
        with self.assertRaises(error.ProcessBadExitStatusException):
            tempesta.start()
