#!/bin/sh

set -e
set -v

# Make things clean.

test -n "$1" && RESULTS=$1 || RESULTS=results.log

test -f Makefile && make -k distclean || :
rm -rf coverage

#rm -rf build
#mkdir build
#cd build

./autogen.sh --prefix="$AUTOBUILD_INSTALL_ROOT" \
  --enable-test-coverage \
  --enable-compile-warnings=error \
  --with-openvz \
  --with-lxc \
  --with-xen-proxy

# If the MAKEFLAGS envvar does not yet include a -j option,
# add -jN where N depends on the number of processors.
case $MAKEFLAGS in
  *-j*) ;;
  *) n=$(getconf _NPROCESSORS_ONLN 2> /dev/null)
    test "$n" -gt 0 || n=1
    n=$(expr $n + 1)
    MAKEFLAGS="$MAKEFLAGS -j$n"
    export MAKEFLAGS
    ;;
esac

make
make install

set -o pipefail
make check 2>&1 | tee "$RESULTS"
make syntax-check 2>&1 | tee -a "$RESULTS"
test -x /usr/bin/lcov && make cov

rm -f *.tar.gz
make dist

if [ -f /usr/bin/rpmbuild ]; then
  if [ -n "$AUTOBUILD_COUNTER" ]; then
    EXTRA_RELEASE=".auto$AUTOBUILD_COUNTER"
  else
    NOW=`date +"%s"`
    EXTRA_RELEASE=".$USER$NOW"
  fi
  rpmbuild --nodeps --define "extra_release $EXTRA_RELEASE" -ta --clean *.tar.gz
fi
