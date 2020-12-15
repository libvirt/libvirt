#!/bin/bash

if [ -z "${CPU_GATHER_PY}" ]; then
    echo >&2 "Do not call this script directly. Use 'cpu-gather.py' instead."
    exit 1
fi

qom_get()
{
    path='/machine/unattached/device[0]'
    echo '{"execute":"qom-get","arguments":{"path":"'$path'",' \
         '"property":"'$1'"},"id":"'$1'"}'
}

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
    else
        qom_get feature-words
        qom_get family
        qom_get model
        qom_get stepping
        qom_get model-id
    fi
)
{"execute":"query-cpu-definitions","id":"definitions"}
{"execute":"quit"}
EOF
