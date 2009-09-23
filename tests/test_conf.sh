#!/bin/sh

test -z "$srcdir" && srcdir=$(pwd)
test -z "$abs_top_srcdir" && abs_top_srcdir=$(pwd)/..
test -z "$abs_top_builddir" && abs_top_builddir=$(pwd)/..
test -z "$abs_srcdir" && abs_srcdir=$(pwd)
test -z "$abs_builddir" && abs_builddir=$(pwd)

if test "$VERBOSE" = yes; then
  set -x
  $abs_top_builddir/tools/virsh --version
fi

. "$srcdir/test-lib.sh"

set -e

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
