#!/bin/bash
set -x
NOK=0
for f in $abs_top_srcdir/tests/confdata/*.conf
do
    ./conftest $f > conftest.$$
    outfile=`echo "$f" | sed s+\.conf$+\.out+`
    diff $outfile conftest.$$ > /dev/null
    if [ $? != 0 ]
    then
        if [ -n "$DEBUG_TESTS" ]; then
            diff -u $outfile conftest.$$
        fi
        echo "$f					FAILED"
        NOK=1
    else
        echo "$f					OK"
    fi
done
rm -f conftest.$$
exit $NOK
