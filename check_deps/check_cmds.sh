#!/bin/bash

check_cmd_present() {
	cmd=$1
	pr=`whereis -b $cmd`
	if [ "$pr" == "$cmd:" ]
	then
		return 1
	fi
	return 0
}

commands=$@
all_ok="true"

for cmd in ${commands[*]}
do
	check_cmd_present $cmd
	present=$?
	if [[ $present -eq 0 ]]
	then
		echo -e "\tCommand '$cmd' is installed"
	else
		echo -e "\tCommand '$cmd' doesn't installed"
		all_ok="false"
	fi
done

if [[ $all_ok == "false" ]]
then
	exit 1
fi
exit 0
