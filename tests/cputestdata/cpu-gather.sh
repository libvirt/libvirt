#!/bin/bash
#
# The cpuid tool can be usually found in a package called "cpuid". If your
# distro does not provide such package, you can find the sources or binary
# packages at http://www.etallen.com/cpuid.html

grep 'model name' /proc/cpuinfo | head -n1

cpuid -1r
echo

python3 <<EOF
from struct import pack, unpack
from fcntl import ioctl
import sys, errno

IA32_ARCH_CAPABILITIES_MSR = 0x10a
KVM_GET_MSRS = 0xc008ae88

def print_msr(msr, via=None):
    if via is None:
        print("MSR:")
    else:
        print("MSR via %s:" % via)
    print("   0x%x: 0x%016x" % (IA32_ARCH_CAPABILITIES_MSR, msr))
    print()

try:
    fd = open("/dev/cpu/0/msr", "rb")
    fd.seek(IA32_ARCH_CAPABILITIES_MSR)
    buf = fd.read(8)
    msr = unpack("=Q", buf)[0]

    print_msr(msr)
    sys.exit(0)
except IOError as e:
    # The MSR is not supported on the host
    if e.errno == errno.EIO:
        sys.exit(0)

try:
    fd = open("/dev/kvm", "r")
    bufIn = pack("=LLLLQ", 1, 0, IA32_ARCH_CAPABILITIES_MSR, 0, 0)
    bufOut = ioctl(fd, KVM_GET_MSRS, bufIn)
    msr = unpack("=LLLLQ", bufOut)[4]

    print_msr(msr, via="KVM")
except IOError as e:
    pass
EOF

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
{"execute":"query-cpu-definitions","id":"definitions"}
{"execute":"quit"}
EOF
