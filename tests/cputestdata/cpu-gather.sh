#!/bin/bash

if [ -z "${CPU_GATHER_PY}" ]; then
    echo >&2 "Do not call this script directly. Use 'cpu-gather.py' instead."
    exit 1
fi

model_expansion()
{
    mode=$1
    model=$2

    echo '{"execute":"query-cpu-model-expansion","arguments":' \
         '{"type":"'"$mode"'","model":'"$model"'},"id":"model-expansion"}'
}

$qemu -machine accel=kvm -cpu host -nodefaults -nographic -qmp stdio <<EOF
{"execute":"qmp_capabilities"}
$(
    if [ "x$model" != x ]; then
        model_expansion full "$model"
    fi
)
{"execute":"query-cpu-definitions","id":"definitions"}
{"execute":"quit"}
EOF
