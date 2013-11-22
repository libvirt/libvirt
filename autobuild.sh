#!/bin/sh

set -e
set -v

# Make things clean.

test -n "$1" && RESULTS=$1 || RESULTS=results.log
: ${AUTOBUILD_INSTALL_ROOT=$HOME/builder}

# If run under the autobuilder, we must use --nodeps with rpmbuild;
# but this can lead to odd error diagnosis for normal development.
nodeps=
if test "${AUTOBUILD_COUNTER+set}"; then
  nodeps=--nodeps
fi

test -f Makefile && make -k distclean || :
rm -rf coverage

rm -rf build
mkdir build
cd build

# Run with options not normally exercised by the rpm build, for
# more complete code coverage.
../autogen.sh --prefix="$AUTOBUILD_INSTALL_ROOT" \
  --enable-expensive-tests \
  --enable-test-coverage \
  --disable-nls \
  --enable-werror \
  --enable-static

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

# set -o pipefail is a bashism; this use of exec is the POSIX alternative
exec 3>&1
st=$(
  exec 4>&1 >&3
  { make check syntax-check 2>&1 3>&- 4>&-; echo $? >&4; } | tee "$RESULTS"
)
exec 3>&-
test "$st" = 0
test -x /usr/bin/lcov && make cov

rm -f *.tar.gz
make dist

if test -n "$AUTOBUILD_COUNTER" ; then
  EXTRA_RELEASE=".auto$AUTOBUILD_COUNTER"
else
  NOW=`date +"%s"`
  EXTRA_RELEASE=".$USER$NOW"
fi

if test -f /usr/bin/rpmbuild ; then
  rpmbuild $nodeps \
     --define "extra_release $EXTRA_RELEASE" \
     --define "_sourcedir `pwd`" \
     -ba --clean libvirt.spec
fi

# Test mingw32 cross-compile
if test -x /usr/bin/i686-w64-mingw32-gcc ; then
  make distclean

  PKG_CONFIG_LIBDIR="/usr/i686-w64-mingw32/sys-root/mingw/lib/pkgconfig:/usr/i686-w64-mingw32/sys-root/mingw/share/pkgconfig" \
  PKG_CONFIG_PATH="$AUTOBUILD_INSTALL_ROOT/i686-w64-mingw32/sys-root/mingw/lib/pkgconfig" \
  CC="i686-w64-mingw32-gcc" \
  ../configure \
    --build=$(uname -m)-w64-linux \
    --host=i686-w64-mingw32 \
    --prefix="$AUTOBUILD_INSTALL_ROOT/i686-w64-mingw32/sys-root/mingw" \
    --enable-expensive-tests \
    --enable-werror \
    --without-libvirtd

  make
  make install

fi

# Test mingw64 cross-compile
if test -x /usr/bin/x86_64-w64-mingw32-gcc ; then
  make distclean

  PKG_CONFIG_LIBDIR="/usr/x86_64-w64-mingw32/sys-root/mingw/lib/pkgconfig:/usr/x86_64-w64-mingw32/sys-root/mingw/share/pkgconfig" \
  PKG_CONFIG_PATH="$AUTOBUILD_INSTALL_ROOT/x86_64-w64-mingw32/sys-root/mingw/lib/pkgconfig" \
  CC="x86_64-w64-mingw32-gcc" \
  ../configure \
    --build=$(uname -m)-w64-linux \
    --host=x86_64-w64-mingw32 \
    --prefix="$AUTOBUILD_INSTALL_ROOT/x86_64-w64-mingw32/sys-root/mingw" \
    --enable-expensive-tests \
    --enable-werror \
    --without-libvirtd

  make
  make install

fi


if test -x /usr/bin/i686-w64-mingw32-gcc && test -x /usr/bin/x86_64-w64-mingw32-gcc ; then
  if test -f /usr/bin/rpmbuild ; then
    rpmbuild $nodeps \
       --define "extra_release $EXTRA_RELEASE" \
       --define "_sourcedir `pwd`" \
       -ba --clean mingw-libvirt.spec
  fi
fi
