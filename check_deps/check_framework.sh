#!/bin/sh

./check_cmds_framework.sh
PF=$?

if [ "$PF" != "0" ]
then
    echo "Don't have required commands on framework node, exiting"
    exit 1
fi

./check_dependencies_v2.py
P2=$?
exit $P2
