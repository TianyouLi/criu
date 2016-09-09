#!/bin/bash
./ioctl "/proc/"$1"/crstat" 38145
rm -rf $1

AOUT="./a.out"
for pid in $(ps aux | grep $AOUT | awk -v PROG="$AOUT" '{if ($11==PROG){print $2}}') ;do
	kill -9 $pid
done
