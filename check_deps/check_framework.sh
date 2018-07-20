#!/bin/bash

# Copyright (C) 2018 Tempesta Technologies, Inc.
# License: GPL2

pr=`whereis -b python2`

if [ "$pr" == "python2:" ]
then
	echo -e "\tpython2 isn't installed. Run apt-get install python2"
	exit 1
else
	echo -e "\tpython2 is installed"
fi

./check_python_dependencies.py
P2=$?
exit $P2
