"""Module to intercept and update an output."""

import datetime
import sys
from typing import TextIO

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2024 Tempesta Technologies, Inc."
__license__ = "GPL2"


class CustomOut(object):
    """Custom output class."""

    def __init__(self, origin: TextIO):
        """
        Init class instance.

        Args:
            origin (TextIO): origin output to intercept, `sys.stdout` or `sys.stderr` as example
        """
        self.origin = origin

    def write(self, data: str):
        """
        Modify and write data to original TextIO.

        Args:
            data (str): data to write
        """
        data = "[{0}] {1}".format(self.now(), data)
        self.origin.write(data)

    def flush(self):
        """
        Flush write buffers, if applicable.

        Patch original TextIO.
        """
        self.origin.flush()

    def fileno(self):
        """
        Returns underlying file descriptor if one exists.

        Patch original TextIO.
        """
        return self.origin.fileno()

    @staticmethod
    def now() -> str:
        """
        Get current datetime.

        Returns:
            (str): formatted datetime
        """
        return datetime.datetime.now().strftime("%b,%d,%y %I:%M:%S,%f")


stdout_inter = CustomOut(origin=sys.stdout)
stderr_inter = CustomOut(origin=sys.stderr)
