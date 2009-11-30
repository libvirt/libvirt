#!/bin/sh

test -z "$srcdir" && srcdir=$(pwd)

. "$srcdir/test-lib.sh"

test_intro $this_test

fail=0
i=0
data_dir=$abs_srcdir/confdata
for f in $(cd "$data_dir" && echo *.conf)
do
    i=`expr $i + 1`
    "$abs_builddir/conftest" "$data_dir/$f" > "$f-actual"
    expected="$data_dir"/`echo "$f" | sed s+\.conf$+\.out+`
    if compare "$expected" "$f-actual"; then
        ret=0
    else
        ret=1
        fail=1
    fi
    test_result $i "$f" $ret
done

test_final $i $fail

(exit $fail); exit $fail
