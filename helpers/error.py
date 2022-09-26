from __future__ import print_function
import sys # for sys.exc_info

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'

class Error(Exception):
    """Base exception class for unrecoverable framework errors.

    Python unittest treats AssertionError as test failure rather than the error.
    Separate exception class is needed to indicate that error happen and
    test framework is not working as expected.
    """
    pass

def assertFalse(expression, msg=''):
    """Raise test framework error if 'expression' is true."""
    if expression:
        raise Error(msg)

def assertTrue(expression, msg=''):
    """Raise test framework error if 'expression' is false."""
    if not expression:
        raise Error(msg)

def bug(msg='', stdout=None, stderr=None):
    """Raise test framework error."""
    exc_info = sys.exc_info()
    if exc_info[1] is not None:
        msg += " (%s: %s)" % (exc_info[0].__name__, exc_info[1])
    if stdout:
        stdout = "\n\t" + "\n\t".join(stdout.decode().splitlines()) + "\n"
        msg += "\nstdout:%s" % stdout
    if stderr:
        stderr = "\n\t" + "\n\t".join(stderr.decode().splitlines()) + "\n"
        msg += "\nstderr:%s" % stderr
    raise Error(msg).with_traceback(exc_info[2])

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
