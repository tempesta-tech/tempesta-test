"""The test decorators."""

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2024 Tempesta Technologies, Inc."
__license__ = "GPL2"

import functools
import time
from cProfile import Profile
from pstats import Stats

import parameterized as pm

from helpers import error, tf_cfg
from test_suite import tester


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

    def wrapper(self: tester.TempestaTest, *args, **kwargs):
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


def get_func_name(func, param_num, params):
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


def get_class_name(cls, num, params_dict: dict):
    if params_dict.get("name"):
        suffix = pm.parameterized.to_safe_name(params_dict["name"])
    else:
        raise AttributeError("Please add the 'name' variable to the class parameters.")

    return f"{cls.__name__}{pm.parameterized.to_safe_name(suffix)}"


def parameterize_class(
    attrs, input_values=None, class_name_func=get_class_name, classname_func=None
):
    """Default wrapper for parametrizing a class from `parameterized` library."""
    return pm.parameterized_class(attrs, input_values, class_name_func, classname_func)


class parameterize(pm.parameterized):
    @classmethod
    def expand(
        cls,
        input_,
        name_func=get_func_name,
        doc_func=None,
        skip_on_empty=False,
        namespace=None,
        **legacy,
    ):
        """Default wrapper for parametrizing a function from `parameterized` library."""
        return super().expand(input_, name_func, doc_func, skip_on_empty, namespace, **legacy)


class param(pm.param):
    """The wrapper for param class from `parameterized` library"""

    ...
