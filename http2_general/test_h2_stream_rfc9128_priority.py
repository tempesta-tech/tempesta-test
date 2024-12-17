"""Functional tests for stream priority."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2023 Tempesta Technologies, Inc."
__license__ = "GPL2"

from http2_general.helpers import H2Base


class TestPriorityParser(H2Base):
    def test_invalid_priority_parameters(self):
        pass

    def test_invalid_urgency(self):
        pass
