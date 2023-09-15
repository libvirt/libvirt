#!/bin/sh

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
    TEST_ARGS="${TEST_ARGS:=--no-suite syntax-check --print-errorlogs}"

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

run_integration() {
    sudo pip3 install --prefix=/usr avocado-framework

    sudo sh -c "echo DefaultLimitCORE=infinity >> /etc/systemd/system.conf" # Explicitly allow storing cores globally
    sudo systemctl daemon-reexec # need to reexec systemd after changing config

    source /etc/os-release  # in order to query the vendor-provided variables
    if test "$ID" = "centos" && test "$VERSION_ID" -eq 8
    then
        DAEMONS="libvirtd virtlockd virtlogd"
    else
        DAEMONS="virtinterfaced virtlockd virtlogd virtnetworkd virtnodedevd virtnwfilterd virtproxyd virtqemud virtsecretd virtstoraged"
    fi
    for daemon in $DAEMONS
    do
        LOG_OUTPUTS="1:file:/var/log/libvirt/${daemon}.log"
        LOG_FILTERS="3:remote 4:event 3:util.json 3:util.object 3:util.dbus 3:util.netlink 3:node_device 3:rpc 3:access 1:*"
        sudo augtool set /files/etc/libvirt/${daemon}.conf/log_filters "'$LOG_FILTERS'" &>/dev/null
        sudo augtool set /files/etc/libvirt/${daemon}.conf/log_outputs "'$LOG_OUTPUTS'" &>/dev/null
        sudo systemctl --quiet stop ${daemon}.service
        sudo systemctl restart ${daemon}.socket
    done

    sudo virsh --quiet net-start default &>/dev/null || true

    cd "$SCRATCH_DIR"
    git clone --depth 1 https://gitlab.com/libvirt/libvirt-tck.git
    cd libvirt-tck
    sudo avocado --config avocado.config run --job-results-dir "$SCRATCH_DIR"/avocado
}
