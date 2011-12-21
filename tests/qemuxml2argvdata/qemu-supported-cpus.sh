#! /bin/sh

. $(dirname $0)/qemu-lib.sh

case $* in
"-M ?")
    faked_machine
    ;;
"-cpu ?")
    faked_cpu | grep -Fv '['
    ;;
*)
    real_qemu "$@"
    ;;
esac
