#!/bin/sh

if test "$VERBOSE" = yes; then
  set -x
  virsh --version
fi

. $srcdir/test-lib.sh

set -e
if test "x$abs_srcdir" = x; then
  abs_srcdir=`pwd`
  abs_builddir=`pwd`
fi

fail=0
i=1
data_dir=$abs_srcdir/confdata
for f in $(cd "$data_dir" && echo *.conf)
do
    "$abs_builddir/conftest" "$data_dir/$f" > "$f-actual"
    expected="$data_dir"/`echo "$f" | sed s+\.conf$+\.out+`
    if compare "$expected" "$f-actual"; then
        msg=OK
    else
        msg=FAILED
        fail=1
    fi
    printf "%2d) %-60s      ... %s\n" $i "$f" $msg
    i=`expr $i + 1`
done

(exit $fail); exit $fail
