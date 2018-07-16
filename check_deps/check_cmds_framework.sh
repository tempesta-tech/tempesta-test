#!/bin/bash

echo "Checking commands on Framework"

./check_cmds.sh curl python2 iptables
exit $?
