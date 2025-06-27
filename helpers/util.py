"""
Utils for the testing framework.
"""

import time
import typing
from string import Template

import run_config

from . import remote, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2019-2025 Tempesta Technologies, Inc."
__license__ = "GPL2"


def __adjust_timeout_for_tcp_segmentation(timeout: int) -> int:
    if run_config.TCP_SEGMENTATION and timeout < 30:
        timeout = 60
    return timeout


def wait_until(
    wait_cond: typing.Callable,
    timeout=5,
    poll_freq=0.01,
    abort_cond: typing.Callable = lambda: False,
    adjust_timeout: bool = False,
) -> typing.Optional[bool]:
    t0 = time.time()

    if adjust_timeout:
        timeout = __adjust_timeout_for_tcp_segmentation(timeout)

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


def get_used_memory():
    stdout, _ = remote.tempesta.run_cmd("free")
    used_memory = int(stdout.decode().split("\n")[1].split()[2])
    return used_memory


def fill_template(template: str | None, properties: dict) -> str | None:
    if template is None:
        return None
    return Template(template).substitute(properties)
