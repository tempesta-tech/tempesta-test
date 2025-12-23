"""The test markers. Must be used as decorators."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"

import functools
import resource
import time
from cProfile import Profile
from pstats import Stats

import parameterized as pm

from helpers import error, tf_cfg, networker
from test_suite import tester
from test_suite.tester import test_logger


def set_mtu(mtu: int, disable_pmtu: bool = False):
    """
    The decorator changes MTU before a test and return the default interface settings after the test.
    """
    def decorator(test):
        @functools.wraps(test)
        def wrapper(self, *args, **kwargs):
            with networker.change_mtu_and_restore_interfaces(mtu=mtu, disable_pmtu=disable_pmtu):
                test(self, *args, **kwargs)
        return wrapper
    return decorator


def set_stress_mtu(test):
    """
    The decorator changes MTU before a test and return the default interface settings after the test.
    Used MTU value from stress_mtu option in General section.
    """
    @functools.wraps(test)
    def wrapper(self, *args, **kwargs):
        with networker.change_mtu_and_restore_interfaces(mtu=int(tf_cfg.cfg.get("General", "stress_mtu")), disable_pmtu=False):
            test(self, *args, **kwargs)
    return wrapper


def extend_tests_with_tso_gro_gso_enable_disable(mtu: int):
    """
    The class decorator. It removes all base tests and
    adds new with suffixes `_tso_gro_gso_enabled` and `_tso_gro_gso_disabled`.
    """
    def class_wrapper(cls):
        tests = {}
        for name, method in list(cls.__dict__.items()):
            if name.startswith('test_'):
                tests[name] = method
                delattr(cls, name)

        def test_tso_gro_gso_enabled(test):
            def wrapper(self, *args, **kwargs):
                with networker.change_and_restore_tso_gro_gso(tso_gro_gso=True, mtu=mtu):
                    test(self, *args, **kwargs)
            return wrapper

        def test_tso_gro_gso_disabled(test):
            def wrapper(self, *args, **kwargs):
                with networker.change_and_restore_tso_gro_gso(tso_gro_gso=False, mtu=mtu):
                    test(self, *args, **kwargs)
            return wrapper

        for test_name, test_method in tests.items():
            # The base methods from marks.Parametrize haven't test_method. So we should skip them
            if test_method is not None:
                setattr(cls, f"{test_name}_tso_gro_gso_enabled", test_tso_gro_gso_enabled(test_method))
                setattr(cls, f"{test_name}_tso_gro_gso_disabled", test_tso_gro_gso_disabled(test_method))

        return cls
    return class_wrapper


def change_tso_gro_gso(*, tso_gro_gso: bool, mtu: int):
    """
    The decorator changes MTU and tso_gro_gso before a test
    and return the default interface settings and tso_gro_gso after the test.
    """
    def decorator(test):
        @functools.wraps(test)
        def wrapper(self, *args, **kwargs):
            with networker.change_and_restore_tso_gro_gso(tso_gro_gso=tso_gro_gso, mtu=mtu):
                test(self, *args, **kwargs)
        return wrapper
    return decorator


def change_tcp_options(mtu: int, tcp_options: dict[str, str]):
    def decorator(test):
        @functools.wraps(test)
        def wrapper(self, *args, **kwargs):
            with networker.change_and_restore_tcp_options(mtu=mtu, tcp_options=tcp_options):
                test(self, *args, **kwargs)
        return wrapper
    return decorator


def change_ulimit(ulimit: int):
    """
    The decorator changes ulimit before a test and return the default value after the test.
    """

    def decorator(test):
        @functools.wraps(test)
        def wrapper(self: tester.TempestaTest, *args, **kwargs):
            soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (ulimit, ulimit))
                test(self, *args, **kwargs)
            finally:
                resource.setrlimit(resource.RLIMIT_NOFILE, (soft_limit, hard_limit))
        return wrapper

    return decorator


def retry_if_not_conditions(test):
    """
    A decorator to retry the test if the testing conditions are not completed.

    This decorator wraps the test function and provides it with up to three
    attempts for execution if an exception error.TestConditionsAreNotCompleted is raised.

    For example:
    @retry_if_not_conditions
    def test_example(self);
        # part of test
        if test_not_condition():
            raise error.TestConditionsAreNotCompleted
        # asserts etc.

    The dmesg asserts should use range in the expect argument:
        self.assertFrangWarning(warning=warning, expected=range(1, 15))
    """

    @functools.wraps(test)
    def wrapper(self: tester.TempestaTest, *args, **kwargs):
        for attempt in range(1, 4):
            try:
                test(self, *args, **kwargs)
                return
            except error.TestConditionsAreNotCompleted:
                test_logger.warning(
                    "Test condition are not completed. Stop services and restart test."
                )
                # Stop all services on failure
                for service in self.get_all_services():
                    service.stop()
                # Wait for 1 second before retrying
                time.sleep(1)

        # If the test fails after 3 attempts, raise an exception
        raise error.TestConditionsAreNotCompleted(self.id(), attempt)

    return wrapper


def deprecated(alt_impl_name):
    """
    Decorator to declare a class and its descendants as deprecated.
    Example ('Foo' is a new alternative implementation which should be used
    instead):

        @util.deprecated("Foo")
        class A(...):
            ...
    """

    def decorator(cls):
        def deprecated_new(new_func):
            def wrap(cls_arg, *args, **kwargs):
                test_logger.warning(
                    "%s must be used instead of deprecated %s" % (alt_impl_name, cls_arg.__name__),
                )
                return new_func(cls_arg)

            return wrap

        setattr(cls, "__new__", staticmethod(deprecated_new(cls.__new__)))
        return cls

    return decorator


def profiled(func):
    """
    Profiling decorator, you can use it as:

        class SomeTester:
            @util.profiled
            def test_func(self):
                ....

    Results will be printed to console.
    """

    @functools.wraps(func)
    def wrap(*args, **kwargs):
        prof = Profile()
        res = prof.runcall(func, *args, **kwargs)
        stats = Stats(prof)
        stats.strip_dirs()
        stats.sort_stats("tottime")
        stats.print_stats(20)
        return res

    return wrap


def _get_func_name(func, param_num, params):
    suffix = params.kwargs.get("name")
    if not suffix:
        if params.args:
            suffix = params.args[0]
        else:
            raise AttributeError(
                "Please use string or integer type as first function parameter "
                "or add the 'name' argument."
            )

    return f"{func.__name__}_{pm.parameterized.to_safe_name(f'{suffix}')}"


def _get_class_name(cls, num, params_dict: dict):
    if params_dict.get("name"):
        suffix = pm.parameterized.to_safe_name(params_dict["name"])
    else:
        raise AttributeError("Please add the 'name' variable to the class parameters.")

    return f"{cls.__name__}{pm.parameterized.to_safe_name(suffix)}"


def parameterize_class(
    attrs, input_values=None, class_name_func=_get_class_name, classname_func=None
):
    """Default wrapper for parametrizing a class from `parameterized` library."""
    return pm.parameterized_class(attrs, input_values, class_name_func, classname_func)


class Parameterize(pm.parameterized):
    @classmethod
    def expand(
        cls,
        input_,
        name_func=_get_func_name,
        doc_func=None,
        skip_on_empty=False,
        namespace=None,
        **legacy,
    ):
        """Default wrapper for parametrizing a function from `parameterized` library."""
        return super().expand(input_, name_func, doc_func, skip_on_empty, namespace, **legacy)


class Param(pm.param):
    """The wrapper for param class from `parameterized` library"""

    ...
