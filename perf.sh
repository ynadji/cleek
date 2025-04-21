#!/bin/bash

if [ $# -ne 1 ]; then
    echo "usage: ./perf.sh path/to/perf.csv"
    exit 1
fi

ros run --load perf.lisp --eval "(in-package :cleek) (progn (run-all-perf-tests \"${1}\") (uiop:quit))"
