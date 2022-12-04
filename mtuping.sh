#!/bin/sh

#
# This program finds the MTU of a remote DSL connection via ping with DF set
# it is written for OpenBSD 6.6, happy easter!
# April 12, 2020 - Peter J. Philipp
#

HI="1472"
LO="504"
MID1=`expr $HI - $LO`
MID2=`expr $MID1 / 2`
PIVOT=$MID2

if [ $1 = "" ] ; then
	echo must specify a destination! 1>&2
	exit 1
fi

echo please wait, program is working...

ping -q -D -c 1 -s$HI $1 > /dev/null 2>&1
if [ $? -eq 0 ]; then
	echo 1500 byte ping works
	exit 0
fi

ping -q -D -c 1 -s$LO $1  > /dev/null 2>&1
if [ $? -eq 0 ]; then
	echo 512 byte ping works
else
	echo "512 byte ping doesn't work, what makes you think anything" \
		"higher will?"  1>&2
	exit 1
fi

DIFFLOHI=$MID1

sleep 1

while [ 1 ]; do
	echo HI: $HI  LO: $LO   PIVOT: $PIVOT  DIFF: $DIFFLOHI
	ping -q -D -c 1 -s$PIVOT $1 > /dev/null 2>&1
	if [ $? -eq 1 ] ; then
		echo changing pivot to HI
		HI=$PIVOT
	else
		LO=$PIVOT
	fi


	MID1=`expr $HI - $LO`
	MID2=`expr $MID1 / 2`
	if [ $LO -eq $PIVOT ]; then
		sleep 1
		PIVOT=`expr $PIVOT + $MID2`
	else
		PIVOT=`expr $PIVOT - $MID2`
	fi

	DIFFLOHI=$MID1

	if [ $DIFFLOHI -lt 0 ] ; then
		echo "[$1] likely filtered, can't go on." 1>&2
		exit 1
	fi

	if [ $LO -eq $HI -o $DIFFLOHI -eq 1 ]; then
		break
	fi

done


ADJUST=`expr $LO + 28`
echo "[$1] MTU is $ADJUST, PING MSS is $LO"

# final ping
ping -D -c 1 -s $LO $1

exit 0
