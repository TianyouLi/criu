#!/bin/bash
AOUT=$1
for pid in $(ps aux | grep $AOUT | awk -v PROG="$AOUT" '{if ($11==PROG){print $2}}') ;do
	kill -9 $pid
done
