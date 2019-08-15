# This script is used to build libvirt inside the container.
#
# You can customize it to your liking, or alternatively use a
# completely different script by passing
#
#  CI_BUILD_SCRIPT=/path/to/your/build/script
#
# to make.

mkdir -p "$CI_CONT_BUILDDIR" || exit 1
cd "$CI_CONT_BUILDDIR"

export VIR_TEST_DEBUG=1
NOCONFIGURE=1 "$CI_CONT_SRCDIR/autogen.sh" || exit 1

# $CONFIGURE_OPTS is a env that can optionally be set in the container,
# populated at build time from the Dockerfile. A typical use case would
# be to pass --host/--target args to trigger cross-compilation
#
# This can be augmented by make local args in $CI_CONFIGURE_ARGS
"$CI_CONFIGURE" $CONFIGURE_OPTS $CI_CONFIGURE_ARGS
if test $? != 0; then
    test -f config.log && cat config.log
    exit 1
fi
find -name test-suite.log -delete

# gl_public_submodule_commit= to disable gnulib's submodule check
# which breaks due to way we clone the submodules
make -j"$CI_SMP" gl_public_submodule_commit= $CI_MAKE_ARGS

if test $? != 0; then \
    LOGS=$(find -name test-suite.log)
    if test "$LOGS"; then
        echo "=== LOG FILE(S) START ==="
        cat $LOGS
        echo "=== LOG FILE(S) END ==="
    fi
    exit 1
fi
