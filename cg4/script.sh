#!/bin/sh

awk '/key/ { print }' output
 
awk '{print $1 " " $NF}' output | awk '$1 < 127 {print}' | cat -n | grep -e f1 -e cc -e c3 -e d2  | awk '$1 > 384 && (length($NF) < 12) {print}'
