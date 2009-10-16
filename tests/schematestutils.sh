#!/bin/sh

test -z "$srcdir" && srcdir=`pwd`
test -z "$abs_srcdir" && abs_srcdir=`pwd`

check_schema () {

DIRS=$1
SCHEMA="$srcdir/../docs/schemas/$2"

n=0
f=0
for dir in $DIRS
do
  XML=`find $abs_srcdir/$dir -name '*.xml'` || exit 1

  for xml in $XML
  do
    n=`expr $n + 1`
    printf "%4d) %.60s  " $n $(basename $(dirname $xml))"/"$(basename $xml)
    cmd="xmllint --relaxng $SCHEMA --noout $xml"
    result=`$cmd 2>&1`
    ret=$?
    if test $ret = 0; then
        echo "OK"
    else
        echo "FAILED"
        echo -e "$cmd\n$result"
        f=`expr $f + 1`
    fi
  done
done
echo "Validated $n files, $f failed"

ret=0
test $f != 0 && ret=255
exit $ret

}
