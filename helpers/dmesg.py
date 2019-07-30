""" Helper for Tempesta system log operations."""

from __future__ import print_function
from contextlib import contextmanager
import re
import time
from . import error, remote, tf_cfg

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2018-2019 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


class DmesgFinder(object):
    """dmesg helper class. """

    def __init__(self):
        self.node = remote.tempesta
        self.log = ''
        self.timestamp = 0
        self.get_log_cmd = (
            'dmesg | tac | grep -m 1 -B 10000 "Start Tempesta DB" | tac')
        self.uptime_cmd = ('grep -o \'^[0-9]*\' /proc/uptime')

    def set_current_timestamp(self):
        """ Dmesg timestamps records with system uptime, so we get current
        timestamp with current system uptime - now we can get all the records
        produced after the current timestamp.
        """
        timestamp, _ = self.node.run_cmd(self.uptime_cmd)
        self.timestamp = int(timestamp)

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

    def msg_after_ts(self, msg):
        """ Find the message in dmesg log after self.timestamp.
        Returns 0 on success, -1 if msg wasn't found and 1 if there are no msg
        and the log is ratelimited.
        """
        ratelimited = False
        for line in self.log.split('\n'):
            if not line:
                break
            ts_match = re.search(r'^\[\s*([0-9]+)', line)
            if not ts_match:
                raise error.Error("bad dmesg line:", line)
            if int(ts_match.group(1)) < self.timestamp:
                continue
            if line.find(msg) >= 0:
                return 0
            if re.findall('net_ratelimit: [\d]+ callbacks suppressed', line):
                ratelimited = True
        return 1 if ratelimited else -1


class DmesgOopsFinder(object):

    def __init__(self):
        self.node = remote.tempesta
        res, _ = self.node.run_cmd("date +%s.%N")
        self.start_time = float(res)

    def update(self):
        cmd = "journalctl -k --since=@{:.6f}".format(self.start_time)
        self.log, _ = self.node.run_cmd(cmd)

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


@contextmanager
def wait_for_msg(msg, timeout, permissive):
    """ Execute a code and waith for the messages in dmesg with the timeout.
    Dmesg may reate limit some messages and our message might be skipped in the
    log. Permissive mode assumes that if msg wasn't found and the log was
    rate limited, then the message was one of the skipped records.
    """
    dmesg = DmesgFinder()
    dmesg.set_current_timestamp()

    yield

    dmesg.update()
    ratelimited = False
    t_start = time.time()
    while t_start + timeout >= time.time():
        res = dmesg.msg_after_ts(msg)
        if res == 0:
            return
        elif res == 1:
            ratelimited = True
        time.sleep(0.01)
    if not permissive:
        raise error.Error("dmesg wait for message timeout")
    if not ratelimited:
        # Ratelimiting messages appear only on next logging operation if
        # previous records were suppressed. This means that if some operation
        # produces a lot of logging and last log records are dropped, then we
        # learn it only with next log record, i.e. next operation.
        # The only good way to fix this is to properly setup system logger,
        # otherwise we either spend too much time on timeouts or observe
        # spurious exceptions.
        tf_cfg.dbg(2, 'No "%s" log record and no ratelimiting' % msg)
