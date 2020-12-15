#!/bin/bash

if [ -z "${CPU_GATHER_PY}" ]; then
    echo >&2 "Do not call this script directly. Use 'cpu-gather.py' instead."
    exit 1
fi

data=`cat`

json()
{
    first=true
    sed -ne '/{"QMP".*/d;
             /{"return": {}}/d;
             /{"timestamp":.*/d;
             /^{/p' <<<"$data" | \
    while read; do
        $first || echo
        first=false
        $(dirname $0)/cpu-reformat.py <<<"$REPLY"
    done
}

json <<<"$data" >$fname.json
if [[ -s $fname.json ]]; then
    echo $fname.json
    if ! grep -q model-expansion $fname.json; then
        echo "Missing query-cpu-model-expansion reply in $name.json" >&2
        exit 1
    fi
    $(dirname $0)/cpu-cpuid.py diff $fname.json
else
    rm $fname.json
fi
