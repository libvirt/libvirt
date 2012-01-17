#! /bin/sh

. ${0%/*}/qemu-lib.sh

case $* in
"-M ?")
    faked_machine
    ;;
"-cpu ?")
    faked_cpu
    ;;
*)
    real_qemu "$@"
    ;;
esac
