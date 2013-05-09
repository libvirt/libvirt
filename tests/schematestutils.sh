#!/bin/sh

check_schema () {

DIRS=$1
SCHEMA="$abs_srcdir/../docs/schemas/$2"

test_intro $this_test

n=0
f=0
for dir in $DIRS
do
  XML=`find $abs_srcdir/$dir -name '*.xml'` || exit 1

  for xml in `echo "$XML" | sort`
  do
    n=`expr $n + 1`
    cmd="xmllint --relaxng $SCHEMA --noout $xml"
    result=`$cmd 2>&1`
    ret=$?

    grep -- '-invalid.xml$' <<< "$xml" 2>&1 >/dev/null
    invalid=$?

    # per xmllint man page, the return codes for validation error
    # are 3 and 4
    if test $invalid -eq 0; then
        if test $ret -eq 4 || test $ret -eq 3; then
            ret=0
        elif test $ret -eq 0; then
            ret=3
        fi
    fi
    test_result $n $(basename $(dirname $xml))"/"$(basename $xml) $ret
    if test "$verbose" = "1" && test $ret != 0 ; then
        printf '%s\n' "$cmd" "$result"
    fi
    if test "$ret" != 0 ; then
        f=`expr $f + 1`
    fi
  done
done

test_final $n $f

ret=0
test $f != 0 && ret=255
exit $ret

}
