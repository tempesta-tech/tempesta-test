#!/bin/bash

# Copyright (C) 2018 Tempesta Technologies, Inc.
# License: GPL2

pr=`whereis -b python2`

if [ "$pr" == "python2:" ]
then
	echo -e "\t\"python2\" required, but not found.\n\tRun \"apt-get install python2\""
	exit 1
else
	echo -e "\tFound python2"
fi

./check_python_dependencies.py
P2=$?
exit $P2
