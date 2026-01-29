#!/bin/sh

# Copyright (C) 2018 Tempesta Technologies, Inc.
# License: GPL2

echo "Testing framework dependencies:"
./check_framework.sh
FW=$?

if [ "$FW" != "0" ]
then
    echo "Status: some of required dependencies are missing."
    exit 1
fi

echo "Packages on test nodes:"
./check_cmds_nodes.py
NODES=$?

if [ "$NODES" != "0" ]
then
    echo "Status: some nodes have missing packages."
    exit 1
fi

echo "Required files on test nodes:"
./check_files_nodes.py
NODES=$?

if [ "$NODES" != "0" ]
then
    echo "Status: some nodes have missing files."
    exit 1
fi

echo "Status: OK."

exit 0
