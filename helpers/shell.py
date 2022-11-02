#!/usr/bin/env python2
from __future__ import print_function

import errno
import json
import os
import unittest

from helpers import remote, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2018 Tempesta Technologies, Inc."
__license__ = "GPL2"

STATE_FILE_NAME = "tests_resume.json"


class DisabledListLoader(object):
    def __init__(self, disabled_list_file):
        self.disabled_list_file = disabled_list_file
        self.has_file = False
        self.disabled = []
        self.disable = False

    def try_load(self):
        """Try to load specified state file"""
        tf_cfg.dbg(2, "Loading disabled file")
        try:
            self.disabled = []
            with open(self.disabled_list_file, "r") as dis_file:
                f = self.__parse_file(dis_file)
                self.disable = f["disable"]
                if self.disable == False:
                    return True
                self.disabled = f["disabled"]
                return True
        except IOError as err:
            if err.errno != errno.ENOENT:
                raise Exception("Error loading disabled tests")
            else:
                tf_cfg.dbg(2, "File %s not found" % self.disabled_list_file)
        return False

    @staticmethod
    def __parse_file(dis_file):
        return json.load(dis_file)


class TestStateLoader(object):
    def __init__(self, state_file):
        self.state_file = state_file
        self.has_file = False
        self.state = []
        self.last_id = None
        self.last_completed = None

    def try_load(self):
        """Try to load specified state file"""
        try:
            with open(self.state_file, "r") as st_file:
                state = self.__parse_file(st_file)
                if state:
                    self.state = state
                    self.last_id = self.state["last_id"]
                    self.last_completed = self.state["last_completed"]
                    return True
        except IOError as err:
            if err.errno != errno.ENOENT:
                raise Exception("Error loading tests state")
            else:
                tf_cfg.dbg(2, "File %s not found" % STATE_FILE_NAME)
        return False

    @staticmethod
    def __parse_file(st_file):
        dump = None
        data = st_file.read()
        if data:
            dump = json.loads(data)
            # convert lists to sets where needed
            dump["inclusions"] = set(dump["inclusions"])
            dump["exclusions"] = set(dump["exclusions"])
        return dump


class TestStateSaver(object):
    def __init__(self, loader, state_file):
        self.inclusions = set()
        self.exclusions = set()
        self.loader = loader
        self.last_id = loader.last_id
        self.last_completed = loader.last_completed
        self.state_file = state_file
        self.has_file = False

    def advance(self, test, after):
        self.last_id = test
        self.last_completed = after
        with open(self.state_file, "w") as st_file:
            self.__build_file(st_file)

    def __build_file(self, st_file):
        dump = dict()
        dump["last_id"] = self.last_id
        dump["last_completed"] = self.last_completed
        # convert sets to lists where needed
        dump["inclusions"] = list(self.inclusions)
        dump["exclusions"] = list(self.exclusions)
        json.dump(dump, st_file)
        self.has_file = True


class TestState(object):
    """Parse saved state"""

    has_file = False
    last_id = None
    last_completed = False
    state_file = os.path.relpath(os.path.join(os.path.dirname(__file__), "..", STATE_FILE_NAME))

    def __init__(self):
        self.loader = TestStateLoader(self.state_file)
        self.saver = TestStateSaver(self.loader, self.state_file)

    def load(self):
        """Load state of test suite from file"""
        self.has_file = self.loader.try_load()

    def advance(self, test, after=False):
        """Set new state of test suite"""
        self.saver.advance(test, after)
        self.has_file = self.has_file or self.saver.has_file
        self.last_id = self.saver.last_id
        self.last_completed = self.saver.last_completed

    def drop(self):
        """Clear tests state"""
        if self.has_file is False:
            return
        try:
            os.unlink(self.state_file)
            self.has_file = False
            self.saver.has_file = False
            self.loader.has_file = False
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                raise


class TestResume(object):
    # Filter is instantiated by TestResume.filter(), passing instance of the
    # matcher to the instance of the filter.

    class Filter(object):
        def __init__(self, matcher):
            self.matcher = matcher
            self.flag = False

        def __call__(self, test):
            if self.flag:
                return True
            if testcase_in(test, [self.matcher.state.last_id]):
                self.flag = True
                return not self.matcher.state.last_completed
            return False

    # Result is instantiated not under our control, so we can't pass a matcher
    # to Result.__init__(). Instead, we dynamically create derived classes
    # that will refer to a certain matcher as a class attribute.
    class Result(unittest.TextTestResult):
        matcher = None

        def __init__(self, *args, **kwargs):
            unittest.TextTestResult.__init__(self, *args, **kwargs)

        def startTest(self, test):
            self.matcher.advance(test.id())
            tf_cfg.log_dmesg(remote.tempesta, "Start test: %s" % test.id())
            return unittest.TextTestResult.startTest(self, test)

        def stopTest(self, test):
            self.matcher.advance(test.id(), after=True)
            res = unittest.TextTestResult.stopTest(self, test)
            tf_cfg.log_dmesg(remote.tempesta, "End test:   %s" % test.id())
            return res

    def __init__(self, state_reader):
        self.from_file = False
        self.state = state_reader

    def set_from_file(self):
        if not self.state.has_file:
            tf_cfg.dbg(2, "Not resuming: File %s not found" % STATE_FILE_NAME)
            return

        if not (
            self.state.saver.inclusions == self.state.loader.state["inclusions"]
            and self.state.saver.exclusions == self.state.loader.state["exclusions"]
        ):
            tf_cfg.dbg(
                1, 'Not resuming from "%s": different filters specified' % self.state.state_file
            )
            return
        # will raise before changing anything if state object is incomplete
        self.set(test=self.state.loader.last_id, after=self.state.loader.last_completed)
        self.from_file = True

    def set(self, test, after=False):
        self.state.advance(test, after)
        self.from_file = False

    def set_filters(self, inclusions, exclusions):
        self.state.saver.inclusions = set(inclusions)
        self.state.saver.exclusions = set(exclusions)

    def __bool__(self):
        return self.state.last_id is not None

    def filter(self):
        if self:
            return TestResume.Filter(self)
        return lambda test: True

    def resultclass(self):
        return type("Result", (TestResume.Result,), {"matcher": self.state})


# I'd use a recursive generator, but `yield from` is python 3.3+
def testsuite_flatten(dest, src):
    if isinstance(src, unittest.TestSuite):
        for t in src:
            testsuite_flatten(dest, t)
    else:
        dest.append(src)


def testcase_in(test, lst):
    test_id = test.id()
    for entry in lst:
        if test_id == entry or test_id.startswith((entry if entry else "") + "."):
            return True
    return False


def test_id_parse(loader, name):
    if name and os.path.exists(name):
        return loader._get_name_from_path(name)
    return name
