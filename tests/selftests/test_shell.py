import json
import unittest
from tempfile import NamedTemporaryFile

from framework.test_suite.shell import TestStateLoader

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2022 Tempesta Technologies, Inc."
__license__ = "GPL2"


class TestTestStateLoader(unittest.TestCase):
    def test_state_file_loaded(self):
        state = {
            "last_id": "selftests.test_shell.TestTestStateLoader.test_load_state_file",
            "last_completed": True,
            "inclusions": [],
            "exclusions": [],
        }
        with NamedTemporaryFile("w") as state_file:
            state_file.write(json.dumps(state))
            state_file.flush()
            loader = TestStateLoader(state_file.name)
            self.assertTrue(loader.try_load())
            self.assertTrue(loader.state)
            self.assertEqual(
                loader.state["last_id"],
                "selftests.test_shell.TestTestStateLoader.test_load_state_file",
            )

    def test_empty_state_file_ignored(self):
        with NamedTemporaryFile() as state_file:
            loader = TestStateLoader(state_file.name)
            self.assertFalse(loader.try_load())
            self.assertFalse(loader.state)
