#!/bin/bash
#
# The cpuid tool can be usually found in a package called "cpuid". If your
# distro does not provide such package, you can find the sources or binary
# packages at http://www.etallen.com/cpuid.html

grep 'model name' /proc/cpuinfo | head -n1

cpuid -1r

echo
qemu=qemu-system-x86_64
for cmd in /usr/bin/$qemu /usr/bin/qemu-kvm /usr/libexec/qemu-kvm; do
    if [[ -x $cmd ]]; then
        qemu=$cmd
        break
    fi
done

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

model=$(
    $qemu -machine accel=kvm -cpu host -nodefaults -nographic -qmp stdio <<EOF
{"execute":"qmp_capabilities"}
$(model_expansion static '{"name":"host"}')
{"execute":"quit"}
EOF
)
model=$(
    echo "$model" | \
    sed -ne 's/^{"return": {"model": {\(.*{.*}\)}}, .*/{\1}/p'
)

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
{"execute":"quit"}
EOF
