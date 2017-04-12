#!/bin/sh
# Run this to generate all the initial makefiles, etc.

die()
{
    echo "error: $1" >&2
    exit 1
}

starting_point=$(pwd)

srcdir=$(dirname "$0")
test "$srcdir" || srcdir=.

cd "$srcdir" || {
    die "Failed to cd into $srcdir"
}

test -f src/libvirt.c || {
    die "$0 must live in the top-level libvirt directory"
}

dry_run=
no_git=
gnulib_srcdir=
extra_args=
while test "$#" -gt 0; do
    case "$1" in
    --dry-run)
        # This variable will serve both as an indicator of the fact that
        # a dry run has been requested, and to store the result of the
        # dry run. It will be ultimately used as return code for the
        # script: 0 means no action is necessary, 2 means that autogen.sh
        # needs to be executed, and 1 is reserved for failures
        dry_run=0
        shift
        ;;
    --no-git)
        no_git=" $1"
        shift
        ;;
    --gnulib-srcdir=*)
        gnulib_srcdir=" $1"
        shift
        ;;
    --gnulib-srcdir)
        gnulib_srcdir=" $1=$2"
        shift
        shift
        ;;
    --system)
        prefix=/usr
        sysconfdir=/etc
        localstatedir=/var
        if test -d $prefix/lib64; then
            libdir=$prefix/lib64
        else
            libdir=$prefix/lib
        fi
        extra_args="--prefix=$prefix --localstatedir=$localstatedir"
        extra_args="$extra_args --sysconfdir=$sysconfdir --libdir=$libdir"
        shift
        ;;
    *)
        # All remaining arguments will be passed to configure verbatim
        break
        ;;
    esac
done
no_git="$no_git$gnulib_srcdir"

gnulib_hash()
{
    local no_git=$1

    if test "$no_git"; then
        echo "no-git"
        return
    fi

    # Compute the hash we'll use to determine whether rerunning bootstrap
    # is required. The first is just the SHA1 that selects a gnulib snapshot.
    # The second ensures that whenever we change the set of gnulib modules used
    # by this package, we rerun bootstrap to pull in the matching set of files.
    # The third ensures that whenever we change the set of local gnulib diffs,
    # we rerun bootstrap to pull in those diffs.
    git submodule status .gnulib | awk '{ print $1 }'
    git hash-object bootstrap.conf
    git ls-tree -d HEAD gnulib/local | awk '{ print $3 }'
}

# Only look into git submodules if we're in a git checkout
if test -d .git || test -f .git; then

    # Check for dirty submodules
    if test -z "$CLEAN_SUBMODULE"; then
        for path in $(git submodule status | awk '{ print $2 }'); do
            case "$(git diff "$path")" in
                *-dirty*)
                    echo "error: $path is dirty, please investigate" >&2
                    echo "set CLEAN_SUBMODULE to discard submodule changes" >&2
                    exit 1
                    ;;
            esac
        done
    fi
    if test "$CLEAN_SUBMODULE" && test -z "$no_git"; then
        if test -z "$dry_run"; then
            echo "Cleaning up submodules..."
            git submodule foreach 'git clean -dfqx && git reset --hard' || {
                die "Cleaning up submodules failed"
            }
        fi
    fi

    # Update all submodules. If any of the submodules has not been
    # initialized yet, it will be initialized now; moreover, any submodule
    # with uncommitted changes will be returned to the expected state
    echo "Updating submodules..."
    git submodule update --init || {
        die "Updating submodules failed"
    }

    # The expected hash, eg. the one computed after the last
    # successful bootstrap run, is stored on disk
    state_file=.git-module-status
    expected_hash=$(cat "$state_file" 2>/dev/null)
    actual_hash=$(gnulib_hash "$no_git")

    if test "$actual_hash" = "$expected_hash" && \
       test -f po/Makevars && test -f AUTHORS; then
        # The gnulib hash matches our expectations, and all the files
        # that can only be generated through bootstrap are present:
        # we just need to run autoreconf. Unless we're performing a
        # dry run, of course...
        if test -z "$dry_run"; then
            echo "Running autoreconf..."
            autoreconf -if || {
                die "autoreconf failed"
            }
        fi
    else
        # Whenever the gnulib submodule or any of the related bits
        # has been changed in some way (see gnulib_hash) we need to
        # run bootstrap again. If we're performing a dry run, we
        # change the return code instead to signal our caller
        if test "$dry_run"; then
            dry_run=2
        else
            echo "Running bootstrap..."
            ./bootstrap$no_git --bootstrap-sync || {
                die "bootstrap failed"
            }
            gnulib_hash >"$state_file"
        fi
    fi
fi

# When performing a dry run, we can stop here
test "$dry_run" && exit "$dry_run"

# If asked not to run configure, we can stop here
test "$NOCONFIGURE" && exit 0

cd "$starting_point" || {
    die "Failed to cd into $starting_point"
}

if test "$OBJ_DIR"; then
    mkdir -p "$OBJ_DIR" || {
        die "Failed to create $OBJ_DIR"
    }
    cd "$OBJ_DIR" || {
        die "Failed to cd into $OBJ_DIR"
    }
fi

if test -z "$*" && test -z "$extra_args" && test -f config.status; then
    echo "Running config.status..."
    ./config.status --recheck || {
        die "config.status failed"
    }
else
    if test -z "$*" && test -z "$extra_args"; then
        echo "I am going to run configure with no arguments - if you wish"
        echo "to pass any to it, please specify them on the $0 command line."
    else
        echo "Running configure with $extra_args $@"
    fi
    "$srcdir/configure" $extra_args "$@" || {
        die "configure failed"
    }
fi

echo
echo "Now type 'make' to compile libvirt."
