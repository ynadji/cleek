#!/bin/bash

#set -x

which cat || exit 2
which zstdcat || exit 2
which gunzip || exit 2

CAT1=cat
CAT2=cat

if [ "${1: -4}" == ".zst" ]; then
    CAT1=zstdcat
fi
if [ "${1: -3}" == ".gz" ]; then
    CAT1="gunzip -c"
fi

if [ "${2: -4}" == ".zst" ]; then
    CAT2=zstdcat
fi
if [ "${2: -3}" == ".gz" ]; then
    CAT2="gunzip -c"
fi

diff <(${CAT1} "${1}" | grep -v '^#') <(${CAT2} "${2}" | grep -v '^#')
