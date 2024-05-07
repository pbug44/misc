#!/bin/sh

awk -F, '{ for (i = 1; i < NF; i++) { a = split($i, b, "/"); print b[2]; }}' output  | sort | uniq -c | sort -rn > output3 

LIONSHARE=`awk '$2 == "0" {print NR}' output3`

awk -v lion=$LIONSHARE 'NR > lion { print $2} ' output3 > iso

awk -F, '{ for (i = 1; i < NF; i++) { print $i; }}' output  | grep -f iso | awk -F/ '{print $1}'

exit 0

