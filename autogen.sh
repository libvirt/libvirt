#!/bin/sh
# Run this to generate all the initial makefiles, etc.
test -n "$srcdir" || srcdir=$(dirname "$0")
test -n "$srcdir" || srcdir=.

olddir=$(pwd)

cd "$srcdir"

(test -f src/libvirt.c) || {
    echo -n "**Error**: Directory "\`$srcdir\'" does not look like the"
    echo " top-level libvirt directory"
    exit 1
}

git submodule update --init || exit 1

autoreconf --verbose --force --install || exit 1

if test "x$1" = "x--system"; then
    shift
    prefix=/usr
    libdir=$prefix/lib
    sysconfdir=/etc
    localstatedir=/var
    if [ -d /usr/lib64 ]; then
      libdir=$prefix/lib64
    fi
    EXTRA_ARGS="--prefix=$prefix --sysconfdir=$sysconfdir --localstatedir=$localstatedir --libdir=$libdir"
fi

cd "$olddir"

if [ "$NOCONFIGURE" = "" ]; then
        $srcdir/configure $EXTRA_ARGS "$@" || exit 1

        if [ "$1" = "--help" ]; then
                exit 0
        else
                echo "Now type 'make' to compile libvirt" || exit 1
        fi
else
        echo "Skipping configure process."
fi
