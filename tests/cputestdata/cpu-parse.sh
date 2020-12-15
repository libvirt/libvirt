#!/bin/bash

if [ -z "${CPU_GATHER_PY}" ]; then
    echo >&2 "Do not call this script directly. Use 'cpu-gather.py' instead."
    exit 1
fi

data=`cat`

if [[ -s $fname.json ]]; then
    if ! grep -q model-expansion $fname.json; then
        echo "Missing query-cpu-model-expansion reply in $name.json" >&2
        exit 1
    fi
    $(dirname $0)/cpu-cpuid.py diff $fname.json
else
    rm $fname.json
fi
