import copy
import errno
import json
import os
import sys
import time
import unittest

from framework.helpers import remote, tf_cfg
from framework.test_suite.tester import test_logger

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

STATE_FILE_NAME = "tests_resume.json"


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
                test_logger.warning(f"File {STATE_FILE_NAME} not found")
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


class _TempestaTestResult(unittest.TextTestResult):
    matcher = TestState()
    max_retries = 3

    def __init__(
        self, rerun_tests: list[unittest.IsolatedAsyncioTestCase], *args, **kwargs
    ) -> None:
        super().__init__(*args, **kwargs)
        self._rerun_tests: list[unittest.IsolatedAsyncioTestCase] = rerun_tests
        self.tests_to_rerun: list[unittest.IsolatedAsyncioTestCase] = []

    def startTest(self, test: unittest.IsolatedAsyncioTestCase) -> None:
        self.matcher.advance(test.id())
        test_logger.info(f"\n\n{'-' * 100}\n" f"Start test '{test.id()}'" f"\n{'-' * 100}")
        tf_cfg.log_dmesg(remote.tempesta, f"Start test: {test.id()}")
        super().startTest(test)

    def stopTest(self, test: unittest.IsolatedAsyncioTestCase) -> None:
        self.matcher.advance(test.id(), after=True)
        super().stopTest(test)
        tf_cfg.log_dmesg(remote.tempesta, f"End test:   {test.id()}")
        test_logger.info(f"\n\n{'-' * 100}\n" f"End test '{test.id()}'" f"\n{'-' * 100}")

    def addFailure(self, test: unittest.IsolatedAsyncioTestCase, err: Exception) -> None:
        self._should_retry(test)
        super().addFailure(test, err)

    def addError(self, test: unittest.IsolatedAsyncioTestCase, err: Exception) -> None:
        self._should_retry(test)
        super().addError(test, err)

    def addUnexpectedSuccess(self, test: unittest.IsolatedAsyncioTestCase) -> None:
        self._should_retry(test)
        super().addUnexpectedSuccess(test)

    def _should_retry(self, test: unittest.IsolatedAsyncioTestCase) -> None:
        """
        Add failed tests to 'tests_to_rerun' list to try again after
        """
        if test in self._rerun_tests:
            self._rerun_tests.remove(test)
            for _ in range(self.max_retries):
                new_test_instance = test.__class__(test._testMethodName)
                self.tests_to_rerun.append(new_test_instance)


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

    def __init__(self, state_reader):
        self.from_file = False
        self.state = state_reader

    def set_from_file(self):
        if not self.state.has_file:
            test_logger.warning("Not resuming: File %s not found" % STATE_FILE_NAME)
            return

        if not (
            self.state.saver.inclusions == self.state.loader.state["inclusions"]
            and self.state.saver.exclusions == self.state.loader.state["exclusions"]
        ):
            test_logger.warning(
                'Not resuming from "%s": different filters specified' % self.state.state_file
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


class _TempestaTestSuite(unittest.TestSuite):
    _tests: list[unittest.IsolatedAsyncioTestCase]

    def __init__(self, tests: list[unittest.IsolatedAsyncioTestCase], repeat: int) -> None:
        self._repeat = repeat
        self._retried_tests = []
        super().__init__(tests)

    def addTests(self, tests: list[unittest.IsolatedAsyncioTestCase]) -> None:
        if isinstance(tests, str):
            raise TypeError("tests must be an iterable of tests, not a string")

        for test in tests:
            for _ in range(self._repeat):
                self.addTest(copy.copy(test))

    def addTest(self, test: unittest.IsolatedAsyncioTestCase) -> None:
        super().addTest(test)
        self._retried_tests.append(test)

    def run(self, result: _TempestaTestResult, debug: bool = False) -> _TempestaTestResult:
        return super().run(result, debug)


class TempestaTestRunner(unittest.TextTestRunner):
    def __init__(
        self, rerun_tests: list[unittest.IsolatedAsyncioTestCase], *args, **kwargs
    ) -> None:
        self._rerun_tests = rerun_tests
        super().__init__(*args, **kwargs)

    def _makeResult(self) -> _TempestaTestResult:
        return _TempestaTestResult(
            self._rerun_tests,
            self.stream,
            self.descriptions,
            self.verbosity,
            durations=self.durations,
        )

    def run(self, tests: _TempestaTestSuite) -> _TempestaTestResult:
        self.stream.writeln(
            """
----------------------------------------------------------------------
Running functional tests...
----------------------------------------------------------------------
            """
        )
        return super().run(tests)

    def _print_rerun_info(
        self, result: _TempestaTestResult, re_result: _TempestaTestResult, time_taken: float
    ) -> None:
        re_result.printErrors()
        self.stream.writeln(re_result.separator2)
        self.stream.writeln(f"Ran {re_result.testsRun} test in {time_taken:.2f}s")
        self.stream.writeln()
        infos = []
        if not result.wasSuccessful():
            self.stream.write("FAILED")
            if re_result.failures:
                infos.append(f"failures={len(re_result.failures)}")
            if re_result.errors:
                infos.append(f"errors={len(re_result.errors)}")
            if re_result.unexpectedSuccesses:
                infos.append(f"unexpected successes={len(re_result.unexpectedSuccesses)}")
        else:
            self.stream.write("OK")
        if re_result.expectedFailures:
            infos.append(f"expected failures={len(re_result.expectedFailures)}")

        self.stream.writeln(f" ({', '.join(infos)}) " if infos else "\n")
        self.stream.flush()

    def _re_run_test_suite(self, result: _TempestaTestResult) -> None:
        self.stream.writeln(
            """
----------------------------------------------------------------------
Run failed tests again ...
----------------------------------------------------------------------
            """
        )
        rerun_tests = list(result.tests_to_rerun)
        result.tests_to_rerun.clear()

        start_time = time.perf_counter()
        re_result = _TempestaTestSuite(tests=rerun_tests, repeat=1)(self._makeResult())
        time_taken = time.perf_counter() - start_time

        if re_result.errors:
            re_errors_set = set(re_result.errors)
            result.errors[:] = [err for err in result.errors if err in re_errors_set]

        if re_result.failures:
            re_failures_set = set(re_result.failures)
            result.failures[:] = [fail for fail in result.failures if fail in re_failures_set]

        if re_result.unexpectedSuccesses:
            re_unexpected_success_set = set(re_result.unexpectedSuccesses)
            result.unexpectedSuccesses[:] = [
                success
                for success in result.unexpectedSuccesses
                if success in re_unexpected_success_set
            ]
        self._print_rerun_info(result, re_result, time_taken)

    def run_test_suite(self, tests: list[unittest.IsolatedAsyncioTestCase], repeat: int) -> int:
        """
        Run the test suite and re-run the failed tests (if they are in the list of rerun tests)
        """
        test_suite = _TempestaTestSuite(tests=tests, repeat=repeat)
        result = self.run(test_suite)

        if result.tests_to_rerun:
            self._re_run_test_suite(result)

        return (
            len(result.failures) > 0
            or len(result.unexpectedSuccesses) > 0
            or len(result.errors) > 0
        )


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
