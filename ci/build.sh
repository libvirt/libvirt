#!/bin/sh

cd "$CI_CONT_SRCDIR"

export CCACHE_BASEDIR="$(pwd)"
export CCACHE_DIR="$CCACHE_BASEDIR/ccache"
export CCACHE_MAXSIZE="500M"
export PATH="$CCACHE_WRAPPERSDIR:$PATH"

# Enable these conditionally since their best use case is during
# non-interactive workloads without having a Shell
if ! [ -t 1 ]; then
    export VIR_TEST_VERBOSE="1"
    export VIR_TEST_DEBUG="1"
fi

GIT_ROOT="$(git rev-parse --show-toplevel)"

# $MESON_OPTS is an env that can optionally be set in the container,
# populated at build time from the Dockerfile. A typical use case would
# be to pass options to trigger cross-compilation
#
# $MESON_ARGS correspond to meson's setup args, i.e. configure args. It's
# populated from a GitLab's job configuration

meson setup build --werror -Dsystem=true $MESON_OPTS $MESON_ARGS || \
(cat build/meson-logs/meson-log.txt && exit 1)

ninja -C build $NINJA_ARGS

run_cmd() {
    printf "\e[32m[RUN COMMAND]: '%s'\e[0m\n" "$*"
    "$@"
}

run_meson_setup() {
    run_cmd meson setup build --error -Dsystem=true $MESON_OPTS $MESON_ARGS || \
    (cat "${GIT_ROOT}/build/meson-logs/meson-log.txt" && exit 1)
}

run_build() {
    test -f $GIT_ROOT/build/build.ninja || run_meson_setup
    run_cmd meson compile -C build $BUILD_ARGS
}

run_dist() {
    test -f $GIT_ROOT/build/build.ninja || run_meson_setup

    # dist is unhappy in local container environment complaining about
    # uncommitted changes in the repo which is often not the case - refreshing
    # git's index solves the problem
    git update-index --refresh
    run_cmd meson dist -C build --no-tests
}

run_test() {
    test -f $GIT_ROOT/build/build.ninja || run_meson_setup
    run_cmd meson test -C build $TEST_ARGS
}

run_codestyle() {
    BUILD_ARGS="libvirt-pot-dep"
    TEST_ARGS="--suite syntax-check --no-rebuild --print-errorlogs"

    run_build
    run_test
}

run_potfile() {
    # since meson would run jobs for each of the following target in parallel,
    # we'd have dependency issues such that one target might depend on a
    # generated file which hasn't been generated yet by the other target, hence
    # we limit potfile job to a single build job (luckily potfile build has
    # negligible performance impact)
    BUILD_ARGS="-j1 libvirt-pot-dep libvirt-pot"

    run_build
}

run_rpmbuild() {
    run_dist
    run_cmd rpmbuild \
                --clean \
                --nodeps \
                --define "_without_mingw 1" \
                -ta build/meson-dist/libvirt-*.tar.xz
}

run_website_build() {
    export DESTDIR="${GIT_ROOT}/install"
    BUILD_ARGS="install-web"

    run_build
}
