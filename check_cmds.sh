#!/bin/bash

check_cmd_present() {
	cmd=$1
	pr=`whereis $cmd | wc -l`
	if [[ "$pr" == "0" ]]
	then
		return 1
	fi
	return 0
}

commands=(wrk curl nginx python2 python3 netstat iptables)
all_ok=true

for cmd in ${commands[*]}
do
	check_cmd_present $cmd
	present=$?
	if [[ $present -eq 0 ]]
	then
		echo "$cmd is installed"
	else
		echo "$cmd doesn't installed"
		all_ok=false
	fi
done

if [[ $all_ok -eq false ]]
then
	exit 1
fi
exit 0
