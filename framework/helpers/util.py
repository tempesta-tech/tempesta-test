"""
Utils for the testing framework.
"""

import asyncio
import inspect
import time
import typing
from string import Template
from typing import Coroutine

import run_config

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2019-2026 Tempesta Technologies, Inc."
__license__ = "GPL2"


def __adjust_timeout_for_tcp_segmentation(timeout: int) -> int:
    if run_config.TCP_SEGMENTATION and timeout < 30:
        timeout = 60
    return timeout


async def wait_until(
    wait_cond: typing.Callable,
    timeout=5,
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
        await asyncio.sleep(run_config.asyncio_freq)

    return True


class ForEach:
    def __init__(self, *objects):
        self.objects = objects

    def __getattr__(self, name):
        attr = getattr(self.objects[0], name)

        if not callable(attr):
            return [getattr(o, name) for o in self.objects]

        is_async = inspect.iscoroutinefunction(attr)

        if not is_async:

            def wrapper(*args, **kwargs):
                return [getattr(o, name)(*args, **kwargs) for o in self.objects]

            return wrapper
        else:

            async def async_wrapper(*args, **kwargs):
                return await asyncio.gather(
                    *[getattr(o, name)(*args, **kwargs) for o in self.objects]
                )

            return async_wrapper

    def __iter__(self):
        for o in self.objects:
            yield o


def fill_template(template: str | None, properties: dict) -> str | None:
    if template is None:
        return None
    return Template(template).substitute(properties)


def encode_chunked(data: str | None, chunk_size: int) -> str:
    if data is None:
        return ""
    result = ""
    while len(data):
        chunk, data = data[:chunk_size], data[chunk_size:]
        result += f"{hex(len(chunk))[2:]}\r\n"
        result += f"{chunk}\r\n"
    return result + "0\r\n\r\n"


def decode_chunked(data: str | None) -> str:
    if data is None:
        return ""
    data = data.split("\r\n")
    data = [(int(length, base=16), chunk) for length, chunk in zip(data[::2], data[1::2])]
    result = ""
    for length, chunk in data:
        if not length:
            return result
        result += chunk[:length]
