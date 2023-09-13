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

run_cmd_quiet() {
    printf "\e[32m[RUN COMMAND]: '%s'\e[0m\n" "$*"
    "$@" 1>/dev/null 2>&1
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
    run_cmd sudo pip3 install --prefix=/usr avocado-framework

    # Explicitly allow storing cores globally
    run_cmd sudo sh -c "echo DefaultLimitCORE=infinity >> /etc/systemd/system.conf"

    # Need to reexec systemd after changing config
    run_cmd sudo systemctl daemon-reexec

    # Source the os-release file to query the vendor-provided variables
    run_cmd . /etc/os-release
    if test "$ID" = "centos" && test "$VERSION_ID" -eq 8
    then
        DAEMONS="libvirtd virtlockd virtlogd"
    else
        DAEMONS="virtinterfaced virtlockd virtlogd virtnetworkd virtnodedevd virtnwfilterd virtproxyd virtqemud virtsecretd virtstoraged"
    fi

    echo "DAEMONS=$DAEMONS"
    for daemon in $DAEMONS
    do
        LOG_OUTPUTS="1:file:/var/log/libvirt/${daemon}.log"
        LOG_FILTERS="3:remote 4:event 3:util.json 3:util.object 3:util.dbus 3:util.netlink 3:node_device 3:rpc 3:access 1:*"
        run_cmd_quiet sudo augtool set /files/etc/libvirt/${daemon}.conf/log_filters "'$LOG_FILTERS'"
        run_cmd_quiet sudo augtool set /files/etc/libvirt/${daemon}.conf/log_outputs "'$LOG_OUTPUTS'"
        run_cmd_quiet sudo systemctl --quiet stop ${daemon}.service
        run_cmd_quiet sudo systemctl restart ${daemon}.socket
    done

    # Make sure the default network is started on all platforms
    # The reason for the '|| true' here is solely that GitLab executes all
    # Shell scripts with -e by default and virsh returns an error if one tries
    # to start a machine/network that is already active which is both fine and
    # should also be a non-fatal error
    run_cmd_quiet sudo virsh --quiet net-start default || true

    # SCRATCH_DIR is normally set inside the GitLab CI job to /tmp/scratch.
    # However, for local executions inside a VM we need to make sure some
    # scratch directory exists and also that it is created outside of /tmp for
    # storage space reasons (if multiple project repos are to be cloned).
    SCRATCH_DIR="${SCRATCH_DIR:=$GIT_ROOT/ci/scratch)}"

    test ! -d "$SCRATCH_DIR" && run_cmd mkdir "$SCRATCH_DIR"
    run_cmd cd "$SCRATCH_DIR"
    run_cmd git clone --depth 1 https://gitlab.com/libvirt/libvirt-tck.git
    run_cmd cd libvirt-tck
    run_cmd sudo avocado --config avocado.config run --job-results-dir "$SCRATCH_DIR"/avocado
}
