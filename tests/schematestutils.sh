#!/bin/sh

(xmllint --version) >/dev/null 2>&1 || skip_test_ 'Missing xmllint'

check_schema () {

DIRS=$1
SCHEMA="$abs_top_srcdir/docs/schemas/$2"

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

    # Alter ret if error was expected.
    case $xml:$ret in
        *-invalid.xml:[34]) ret=0 ;;
        *-invalid.xml:0)    ret=3 ;;
    esac

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
