# This script is used to build libvirt inside the container.
#
# You can customize it to your liking, or alternatively use a
# completely different script by passing
#
#  CI_BUILD_SCRIPT=/path/to/your/build/script
#
# to make.

cd "$CI_CONT_SRCDIR"

export VIR_TEST_DEBUG=1

# $MESON_OPTS is an env that can optionally be set in the container,
# populated at build time from the Dockerfile. A typical use case would
# be to pass options to trigger cross-compilation

meson build --werror $MESON_OPTS $CI_MESON_ARGS || \
(cat build/meson-logs/meson-log.txt && exit 1)

ninja -C build $CI_NINJA_ARGS
