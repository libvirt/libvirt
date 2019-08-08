#!/bin/bash

function die {
    echo $@ >&2
    exit 1
}

function show_help {
    cat << EOF
Usage: ${0##*/} -[hqn] [PATH]

Clear out any XATTRs set by libvirt on all files that have them.
The idea is to reset refcounting, should it break.

  -h    display this help and exit
  -q    quiet (don't print which files are being fixed)
  -n    dry run; don't remove any XATTR just report the file name

PATH can be specified to refine search to only to given path
instead of whole root ('/'), which is the default.
EOF
}

QUIET=0
DRY_RUN=0
DIR="/"

# So far only qemu and lxc drivers use security driver.
URI=("qemu:///system"
     "lxc:///system")

# On Linux we use 'trusted' namespace, on FreeBSD we use 'system'
# as there is no 'trusted'.
LIBVIRT_XATTR_PREFIXES=("trusted.libvirt.security"
                        "system.libvirt.security")

if [ `whoami` != "root" ]; then
    die "Must be run as root"
fi

while getopts hqn opt; do
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
        *)
            show_help >&2
            exit 1
            ;;
    esac
done

shift $((OPTIND - 1))
if [ $# -gt 0 ]; then
    DIR=$1
fi

if [ ${DRY_RUN} -eq 0 ]; then
    for u in ${URI[*]} ; do
        if [ -n "`virsh -q -c $u list 2>/dev/null`" ]; then
            die "There are still some domains running for $u"
        fi
    done
fi


declare -a XATTRS
for i in "dac" "selinux"; do
    for p in ${LIBVIRT_XATTR_PREFIXES[@]}; do
        XATTRS+=("$p.$i" "$p.ref_$i" "$p.timestamp_$i")
    done
done

for p in ${LIBVIRT_XATTR_PREFIXES[*]}; do
    for i in $(getfattr -R -d -m ${p} --absolute-names ${DIR} 2>/dev/null | grep "^# file:" | cut -d':' -f 2); do
        echo $i;
        if [ ${DRY_RUN} -ne 0 ]; then
            getfattr -d -m $p --absolute-names $i | grep -v "^# file:"
            continue
        fi

        if [ ${QUIET} -eq 0 ]; then
            echo "Fixing $i";
        fi
        for x in ${XATTRS[*]}; do
            setfattr -x $x $i
        done
    done
done
