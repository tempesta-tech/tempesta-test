"""
Utils for the testing framework.
"""

import functools
import time
from cProfile import Profile
from pstats import Stats
from string import Template

from . import error, remote, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2019 Tempesta Technologies, Inc."
__license__ = "GPL2"


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

    def wrapper(self, *args, **kwargs):
        for attempt in range(1, 4):
            try:
                test(self, *args, **kwargs)
                return
            except error.TestConditionsAreNotCompleted:
                tf_cfg.dbg(1, "Test condition are not completed. Stop services and restart test.")
                # Stop all services on failure
                for service in self.get_all_services():
                    service.stop()
                # Wait for 1 second before retrying
                time.sleep(1)

        # If the test fails after 3 attempts, raise an exception
        raise error.TestConditionsAreNotCompleted(self.id(), attempt)

    # we need to change name of function to work correctly with parametrize
    wrapper.__name__ = test.__name__
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
                tf_cfg.dbg(
                    6,
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


def wait_until(wait_cond, timeout=5, poll_freq=0.01, abort_cond=lambda: False):
    t0 = time.time()

    while wait_cond():
        t = time.time()
        if t - t0 > timeout:
            return not wait_cond()  # check wait_cond for the last time
        if abort_cond():
            return None
        time.sleep(poll_freq)

    return True


class ForEach:
    def __init__(self, *objects):
        self.objects = objects

    def __getattr__(self, name):
        if not callable(getattr(self.objects[0], name)):
            return [getattr(o, name) for o in self.objects]

        def wrapper(*args, **kwargs):
            return [getattr(o, name)(*args, **kwargs) for o in self.objects]

        return wrapper

    def __iter__(self):
        for o in self.objects:
            yield o


def getsockname_safe(s):
    try:
        return s.getsockname()
    except Exception as e:
        tf_cfg.dbg(6, f"Failed to get socket name: {e}")
        return None


def get_used_memory():
    stdout, _ = remote.tempesta.run_cmd("free")
    used_memory = int(stdout.decode().split("\n")[1].split()[2])
    return used_memory


def fill_template(template, properties):
    return Template(template).substitute(properties)
