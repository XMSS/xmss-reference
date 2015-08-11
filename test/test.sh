#!/bin/bash

DIR=$(dirname $0)
#for i in `ls $DIR/test* | grep -v \.c$ | grep -v \.sh$`;do ($i || echo 666) | bc | grep -v ^0$;done 
for i in `ls $DIR/test* | grep -v \.c$ | grep -v \.sh$`;do ($i || echo 666) ;done 
exit 0
