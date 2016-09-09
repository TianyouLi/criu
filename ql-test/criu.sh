#!/bin/bash
setsid $1 $2 < /dev/null &> $1".log" &
sleep 1
for pid in $(ps aux | grep $1 | awk -v PROG="$1" '{if ($11==PROG){print $2}}') ;do
	echo "Dump "$pid
	mkdir $pid
	cd $pid
	criu dump -t $pid -Q -vvv --tcp-established && echo OK

#	sleep 2
#	criu restore -d -vvv --tcp-established
#	cd ..
#	./kill.sh $pid

	exit
done
