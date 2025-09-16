"""
Utils for the testing framework.
"""
import gc
import time
import typing
from string import Template

import psutil

import run_config

from . import remote, error

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
    """Get used system memory in KB."""
    stdout, _ = remote.tempesta.run_cmd("free")
    used_memory = int(stdout.decode().split("\n")[1].split()[2])
    return used_memory


def get_used_python_memory():
    """Get used python memory in KB."""
    return psutil.Process().memory_info().rss // 1024


def check_memory_consumption(
        *,
        system_memory_before: int,
        python_memory_before: int = None,
        memory_leak_threshold: int | None = run_config.MEMORY_LEAK_THRESHOLD,
) -> str:
    if python_memory_before:
        gc.collect()
        time.sleep(1)
        python_memory_after = get_used_python_memory()
        delta_python = python_memory_after - python_memory_before
    else:
        python_memory_after = None
        delta_python = 0

    system_memory_after = get_used_memory()
    delta_used_memory = system_memory_after - delta_python - system_memory_before

    msg=(
        f"Before: system memory: {system_memory_before} KB;\n"
        f"Before: python memory: {python_memory_before} KB;\n"
        f"After: system memory: {system_memory_after} KB;\n"
        f"After: python memory: {python_memory_after} KB;\n"
        f"Delta: {delta_used_memory} KB\n"
    )

    if memory_leak_threshold and delta_used_memory >= memory_leak_threshold:
        raise error.MemoryConsumptionException(msg, delta_used_memory, memory_leak_threshold)

    return msg


def fill_template(template: str | None, properties: dict) -> str | None:
    if template is None:
        return None
    return Template(template).substitute(properties)
