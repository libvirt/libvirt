#!/bin/sh

cd "$CI_CONT_SRCDIR"

export VIR_TEST_DEBUG=1

# $MESON_OPTS is an env that can optionally be set in the container,
# populated at build time from the Dockerfile. A typical use case would
# be to pass options to trigger cross-compilation

meson setup build --werror $MESON_OPTS $CI_MESON_ARGS || \
(cat build/meson-logs/meson-log.txt && exit 1)

ninja -C build $CI_NINJA_ARGS
