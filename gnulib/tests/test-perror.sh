#!/bin/sh

tmpfiles=""
trap 'rm -fr $tmpfiles' 1 2 3 15

# Test NULL prefix. Result should not contain a number.
tmpfiles="$tmpfiles t-perror.tmp"
./test-perror${EXEEXT} 2>&1 >/dev/null | LC_ALL=C tr -d '\r' > t-perror.tmp
if grep '[0-9]' t-perror.tmp > /dev/null; then
  rm -fr $tmpfiles; exit 1
fi

# Test empty prefix. Result should be the same.
tmpfiles="$tmpfiles t-perror1.tmp"
./test-perror${EXEEXT} '' 2>&1 >/dev/null | LC_ALL=C tr -d '\r' > t-perror1.tmp
diff t-perror.tmp t-perror1.tmp
test $? = 0 || { rm -fr $tmpfiles; exit 1; }

# Test non-empty prefix.
tmpfiles="$tmpfiles t-perror2.tmp t-perror3.tmp"
./test-perror${EXEEXT} 'foo' 2>&1 >/dev/null | LC_ALL=C tr -d '\r' > t-perror3.tmp
sed -e 's/^/foo: /' < t-perror.tmp > t-perror2.tmp
diff t-perror2.tmp t-perror3.tmp
test $? = 0 || { rm -fr $tmpfiles; exit 1; }

rm -fr $tmpfiles
exit 0
