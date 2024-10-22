"""
Utils for the testing framework.
"""

import time
from string import Template

from . import remote, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2019-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"


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


def modify_cmd(cmd: str, wrap_sh: bool = False, with_sudo: bool = False) -> str:
    """
    Updated command line.

    Args:
        cmd (str): command line to update
        wrap_sh (bool): if True, the command will be wrapped with `sh`, i.e. `sh -c '<command>'`
            https://manpages.ubuntu.com/manpages/trusty/man1/sh.1posix.html
        with_sudo (bool): if True, `sudo` prefix will be added at beginning of the `cmd`

    Returns:
        (str): updated command line
    """
    if wrap_sh:
        cmd = f'sh -c "{cmd}"'
        tf_cfg.dbg(5, f"The command was wrapped with shell: `{cmd}`")

    if with_sudo:
        cmd = f"sudo {cmd}"
        tf_cfg.dbg(5, f"The command was updated: added sudo-prefix `{cmd}`")

    return cmd
