#!/bin/sh
# Run this to generate all the initial makefiles, etc.

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.

THEDIR=`pwd`
cd $srcdir
DIE=0

(autopoint --version) < /dev/null > /dev/null 2>&1 || {
        echo
        echo "You must have autopoint installed to compile libvirt."
        echo "Download the appropriate package for your distribution,"
        echo "or see http://www.gnu.org/software/gettext"
        DIE=1
}

(autoconf --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have autoconf installed to compile libvirt."
	echo "Download the appropriate package for your distribution,"
	echo "or see http://www.gnu.org/software/autoconf"
	DIE=1
}

(libtool --version) < /dev/null > /dev/null 2>&1 || {
	echo
	echo "You must have libtool installed to compile libvirt."
	echo "Download the appropriate package for your distribution,"
	echo "or see http://www.gnu.org/software/libtool"
	DIE=1
}

(automake --version) < /dev/null > /dev/null 2>&1 || {
	echo
	DIE=1
	echo "You must have automake installed to compile libvirt."
	echo "Download the appropriate package for your distribution,"
	echo "or see http://www.gnu.org/software/automake"
}

if test "$DIE" -eq 1; then
	exit 1
fi

test -f src/libvirt.c || {
	echo "You must run this script in the top-level libvirt directory"
	exit 1
}

if test -z "$*"; then
	echo "I am going to run ./configure with no arguments - if you wish "
        echo "to pass any to it, please specify them on the $0 command line."
fi

# Ensure that whenever we pull in a gnulib update or otherwise change to a
# different version (i.e., when switching branches), we also rerun ./bootstrap.
curr_status=.git-module-status
t=$(git submodule status)
if test "$t" = "$(cat $curr_status 2>/dev/null)"; then
    : # good, it's up to date
else
  echo running bootstrap...
  ./bootstrap && echo "$t" > $curr_status
fi

# Automake requires that ChangeLog exist.
touch ChangeLog

autoreconf -if

cd $THEDIR

if test x$OBJ_DIR != x; then
    mkdir -p "$OBJ_DIR"
    cd "$OBJ_DIR"
fi

$srcdir/configure "$@" && {
    echo
    echo "Now type 'make' to compile libvirt."
}
