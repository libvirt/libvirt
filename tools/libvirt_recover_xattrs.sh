#!/bin/bash

function die {
    echo $@ >&2
    exit 1
}

function show_help {
    cat << EOF
Usage: ${0##*/} -[hqnu] [PATH ...]

Clear out any XATTRs set by libvirt on all files that have them.
The idea is to reset refcounting, should it break.

  -h    display this help and exit
  -q    quiet (don't print which files are being fixed)
  -n    dry run; don't remove any XATTR just report the file name
  -u    unsafe; don't check whether there are running VMs; PATH must be specified

PATH can be specified to refine search to only to given path
instead of whole root ('/'), which is the default.
EOF
}

QUIET=0
DRY_RUN=0
UNSAFE=0

# So far only qemu and lxc drivers use security driver.
URI=("qemu:///system"
     "lxc:///system")

if [ $(whoami) != "root" ]; then
    die "Must be run as root"
fi

while getopts hqnu opt; do
    case $opt in
        h)
            show_help
            exit 0
            ;;
        q)
            QUIET=1
            ;;
        n)
            DRY_RUN=1
            ;;
        u)
            UNSAFE=1
            ;;
        *)
            show_help >&2
            exit 1
            ;;
    esac
done

case $(uname -s) in
    Linux)
        XATTR_PREFIX="trusted.libvirt.security"
        ;;

    FreeBSD)
        XATTR_PREFIX="system.libvirt.security"
        ;;

    *)
        die "$0 is not supported on this platform"
        ;;
esac


if [ ${DRY_RUN} -eq 0 ] && [ ${UNSAFE} -eq 0 ]; then
    for u in ${URI[*]} ; do
        if [ -n "`virsh -q -c $u list 2>/dev/null`" ]; then
            die "There are still some domains running for $u"
        fi
    done
fi


declare -a XATTRS
for i in "dac" "selinux"; do
    XATTRS+=("$XATTR_PREFIX.$i" "$XATTR_PREFIX.ref_$i" "$XATTR_PREFIX.timestamp_$i")
done

fix_xattrs() {
    local DIR="$1"

    for i in $(getfattr -R -d -m ${XATTR_PREFIX} --absolute-names ${DIR} 2>/dev/null | grep "^# file:" | cut -d':' -f 2); do
        if [ ${DRY_RUN} -ne 0 ]; then
            getfattr -d -m ${XATTR_PREFIX} --absolute-names $i
            continue
        fi

        if [ ${QUIET} -eq 0 ]; then
            echo "Fixing $i";
        fi
        for x in ${XATTRS[*]}; do
            setfattr -x $x $i
        done
    done
}


shift $((OPTIND - 1))
if [ $# -gt 0 ]; then
    for arg in "$@"
    do
        fix_xattrs "$arg"
    done
else
    if [ ${UNSAFE} -eq 1 ]; then
        die "Unsafe mode (-u) requires explicit 'PATH' argument"
    fi
    fix_xattrs "/"
fi
