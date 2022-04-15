#!/bin/bash

# Copyright (C) 2018 Tempesta Technologies, Inc.
# License: GPL2

pr=`whereis -b python3`

if [ "$pr" == "python3:" ]
then
	echo -e "\t\"python3\" required, but not found.\n\tRun \"apt-get install python3\""
	exit 1
else
	echo -e "\tFound python3"
fi

./check_python_dependencies.py
P2=$?
exit $P2
