"""
Utils for the testing framework.
"""
import functools
import time
from cProfile import Profile
from pstats import Stats

from . import tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2019 Tempesta Technologies, Inc."
__license__ = "GPL2"


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
