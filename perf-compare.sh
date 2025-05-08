#!/bin/bash

if [ $# -ne 2 ]; then
  echo "usage: perf-compare.sh NEW.csv OLD.csv"
  exit 1
fi

join -t, ${1} ${2} | awk -F, '{OFS=","} { if ( $1 == "test-name" ) { print $1,$2,$3,$4,$5,$6,$7; } else { printf("%s,", $1); for ( i=2;i<8;i++ ) { j=i+6; printf("%2.1f%%,", ($j-$i)/$i*100); }; print ""; }}' | sed 's/,$//'
