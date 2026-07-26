"""
Utils for the testing framework.
"""

import asyncio
import inspect
import time
import typing
from string import Template

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


async def wait_until_event(
    wait_cond: typing.Callable,
    event: asyncio.Event,
    timeout=5,
    abort_cond: typing.Callable = lambda: False,
    adjust_timeout: bool = False,
) -> typing.Optional[bool]:
    """
    Asynchronously waits for a condition to clear, synchronized by an event.

    This function loops and yields control to the event loop via `event.wait()`.
    It re-evaluates the wait condition every time the event fires or a timeout
    slice expires, while managing a strict overall time.

    Args:
        wait_cond: A callable predicate. The loop continues as long as this returns True.
        event: An asyncio Event signaling potential state changes in the system.
        timeout: Total maximum time allowed for the wait operation, in seconds.
        abort_cond: A callable predicate to trigger an early exit. If True, returns None.
        adjust_timeout: If True, modifies the initial timeout value for TCP segmentation.

    Returns:
        True: The wait condition successfully evaluated to False within the timeout.
        False: The total timeout expired, and the wait condition remains True.
        None: The execution was explicitly aborted by the abort condition.
    """
    t0 = time.time()

    if adjust_timeout:
        timeout = __adjust_timeout_for_tcp_segmentation(timeout)

    while wait_cond():
        if abort_cond():
            return None

        rem_timeout = timeout - (time.time() - t0)
        if rem_timeout <= 0:
            return not wait_cond()

        try:
            await asyncio.wait_for(event.wait(), timeout=rem_timeout)
            event.clear()
        except asyncio.TimeoutError:
            return not wait_cond()

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
