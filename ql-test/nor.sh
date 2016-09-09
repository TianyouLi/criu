#!/bin/bash
setsid ./listen < /dev/null &> "a.log" &
sleep 1
./client </dev/null>/dev/null &
sleep 1
for pid in $(ps aux | grep "./listen" | awk -v PROG="./listen" '{if ($11==PROG){print $2}}') ;do
	echo "Dump "$pid
	mkdir $pid
	cd $pid
	criu dump -t $pid -vvv --tcp-established && echo OK
	exit
done
