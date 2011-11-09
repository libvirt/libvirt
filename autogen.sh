#!/bin/sh
# Run this to generate all the initial makefiles, etc.

srcdir=`dirname "$0"`
test -z "$srcdir" && srcdir=.

THEDIR=`pwd`
cd "$srcdir"

test -f src/libvirt.c || {
    echo "You must run this script in the top-level libvirt directory"
    exit 1
}


EXTRA_ARGS=
no_git=
if test "x$1" = "x--no-git"; then
  no_git=" $1"
  shift
fi
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
    echo "Running ./configure with $EXTRA_ARGS $@"
else
    if test -z "$*" && test ! -f "$THEDIR/config.status"; then
        echo "I am going to run ./configure with no arguments - if you wish "
        echo "to pass any to it, please specify them on the $0 command line."
    fi
fi

# Compute the hash we'll use to determine whether rerunning bootstrap
# is required.  The first is just the SHA1 that selects a gnulib snapshot.
# The second ensures that whenever we change the set of gnulib modules used
# by this package, we rerun bootstrap to pull in the matching set of files.
# The third ensures that whenever we change the set of local gnulib diffs,
# we rerun bootstrap to pull in those diffs.
bootstrap_hash()
{
    git submodule status | sed 's/^[ +-]//;s/ .*//'
    git hash-object bootstrap.conf
    git ls-tree -d HEAD gnulib/local | awk '{print $3}'
}

# Ensure that whenever we pull in a gnulib update or otherwise change to a
# different version (i.e., when switching branches), we also rerun ./bootstrap.
# Also, running 'make rpm' tends to litter the po/ directory, and some people
# like to run 'git clean -x -f po' to fix it; but only ./bootstrap regenerates
# the required file po/Makevars.
# Only run bootstrap from a git checkout, never from a tarball.
if test -d .git; then
    curr_status=.git-module-status
    t=$(bootstrap_hash; git diff .gnulib)
    if test "$t" = "$(cat $curr_status 2>/dev/null)" \
        && test -f "po/Makevars"; then
        # good, it's up to date, all we need is autoreconf
        autoreconf -if
    else
        echo running bootstrap$no_git...
        ./bootstrap$no_git --bootstrap-sync && bootstrap_hash > $curr_status \
            || { echo "Failed to bootstrap, please investigate."; exit 1; }
    fi
fi

cd "$THEDIR"

if test "x$OBJ_DIR" != x; then
    mkdir -p "$OBJ_DIR"
    cd "$OBJ_DIR"
fi

if test -z "$*" && test -f config.status; then
    ./config.status --recheck
else
    $srcdir/configure $EXTRA_ARGS "$@"
fi && {
    echo
    echo "Now type 'make' to compile libvirt."
}
