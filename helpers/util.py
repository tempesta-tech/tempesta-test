"""
Utils for the testing framework.
"""
from cProfile import Profile
from pstats import Stats
import functools

from . import tf_cfg

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


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
                tf_cfg.dbg(5, "%s must be used instead of deprecated %s"
                           % (alt_impl_name, cls_arg.__name__))
                return new_func(cls_arg, *args, **kwargs)
            return wrap

        setattr(cls, '__new__', staticmethod(deprecated_new(cls.__new__)))
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
        stats.sort_stats('tottime')
        stats.print_stats(20)
        return res
    return wrap
