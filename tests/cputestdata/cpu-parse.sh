#!/bin/bash

if [ -z "${CPU_GATHER_PY}" ]; then
    echo >&2 "Do not call this script directly. Use 'cpu-gather.py' instead."
    exit 1
fi

data=`cat`
