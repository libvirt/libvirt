candidates="/usr/bin/qemu-kvm
            /usr/libexec/qemu-kvm
            /usr/bin/qemu-system-x86_64
            /usr/bin/qemu"
qemu=
for candidate in $candidates; do
    if test -x $candidate; then
        qemu=$candidate
        break
    fi
done

real_qemu()
{
    if test x$qemu != x; then
        exec $qemu "$@"
    else
        return 1
    fi
}

faked_machine()
{
    echo "pc"
}

faked_cpu()
{
    cat <<EOF
x86       Opteron_G3
x86       Opteron_G2
x86       Opteron_G1
x86          Nehalem
x86           Penryn
x86           Conroe
x86           [n270]
x86         [athlon]
x86       [pentium3]
x86       [pentium2]
x86        [pentium]
x86            [486]
x86        [coreduo]
x86         [qemu32]
x86          [kvm64]
x86       [core2duo]
x86         [phenom]
x86         [qemu64]
x86           [host]
EOF
}
