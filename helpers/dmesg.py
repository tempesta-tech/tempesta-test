""" Helper for Tempesta system log operations."""

from __future__ import print_function
import re
from . import remote, tf_cfg

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class DmesgFinder(object):
    """dmesg helper class. """

    def __init__(self):
        self.node = remote.tempesta
        self.log = ''
        self.get_log_cmd = (
            'dmesg | tac | grep -m 1 -B 10000 "Start Tempesta DB" | tac')

    def update(self):
        """Get log from the last run."""
        self.log, _ = self.node.run_cmd(self.get_log_cmd)

    def show(self):
        """Show tempesta system log."""
        print(self.log)

    def warn_count(self, warn_str):
        """Count occurrences of given string in system log. Normally used to
        count warnings during test.
        """
        match = re.findall(warn_str, self.log)
        return len(match)

class DmesgStatefulFinder(object):

    def __init__(self):
        self.node = remote.tempesta

    def start(self):
        try:
            l,_ = self.node.run_cmd("dmesg|wc -l")
            self.skip = int(l)
            tf_cfg.dbg(3, "Dmesg detector skip %i lines" % self.skip)
        except Exception as e:
            tf_cfg.dbg(2, "Error while dmesg tracker init: %s" % str(e))
            raise e

    def update(self):
        self.log, _ = self.node.run_cmd("dmesg | tail -n +%i" % (self.skip + 1))

    def warn_count(self, msg):
        match = re.findall(msg, self.log)
        return len(match)

WARN_GENERIC = 'Warning: '
WARN_SPLIT_ATTACK = 'Warning: Paired request missing, HTTP Response Splitting attack?'

def count_warnings(msg):
    """Get system log and count occurrences of single warnings."""
    dmesg = DmesgFinder()
    dmesg.update()
    return dmesg.warn_count(msg)
