#!/usr/bin/python3

import os
import subprocess
import sys

from helpers import prepare, remote, tf_cfg

__author__ = "Tempesta Technologies, Inc."
__copyright__ = "Copyright (C) 2017-2018 Tempesta Technologies, Inc."
__license__ = "GPL2"

tf_cfg.cfg.check()

# Redirect stderr into a file
tee = subprocess.Popen(
    ["tee", "-i", tf_cfg.cfg.get("General", "log_file")], stdin=subprocess.PIPE, stdout=sys.stderr
)
sys.stderr.flush()
os.dup2(tee.stdin.fileno(), sys.stderr.fileno())
tee.stdin.close()

# Verbose level for unit tests must be > 1.
v_level = int(tf_cfg.cfg.get("General", "Verbose")) + 1

remote.connect()

prepare.configure()
