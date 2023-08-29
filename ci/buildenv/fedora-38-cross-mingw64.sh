# THIS FILE WAS AUTO-GENERATED
#
#  $ lcitool manifest ci/manifest.yml
#
# https://gitlab.com/libvirt/libvirt-ci

function install_buildenv() {
    dnf update -y
    dnf install -y \
        augeas \
        bash-completion \
        ca-certificates \
        ccache \
        codespell \
        cpp \
        cppi \
        diffutils \
        dwarves \
        ebtables \
        firewalld-filesystem \
        git \
        glibc-langpack-en \
        grep \
        iproute \
        iproute-tc \
        iptables \
        iscsi-initiator-utils \
        kmod \
        libnbd-devel \
        libxml2 \
        libxslt \
        lvm2 \
        make \
        meson \
        nfs-utils \
        ninja-build \
        numad \
        perl-base \
        polkit \
        python3 \
        python3-docutils \
        python3-flake8 \
        qemu-img \
        rpcgen \
        rpm-build \
        scrub \
        sed \
        systemd-rpm-macros
    dnf install -y \
        mingw64-curl \
        mingw64-dlfcn \
        mingw64-gcc \
        mingw64-gettext \
        mingw64-glib2 \
        mingw64-gnutls \
        mingw64-headers \
        mingw64-libssh2 \
        mingw64-libxml2 \
        mingw64-pkg-config \
        mingw64-portablexdr \
        mingw64-readline
    rpm -qa | sort > /packages.txt
    mkdir -p /usr/libexec/ccache-wrappers
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/x86_64-w64-mingw32-cc
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/x86_64-w64-mingw32-gcc
}

export CCACHE_WRAPPERSDIR="/usr/libexec/ccache-wrappers"
export LANG="en_US.UTF-8"
export MAKE="/usr/bin/make"
export NINJA="/usr/bin/ninja"
export PYTHON="/usr/bin/python3"

export ABI="x86_64-w64-mingw32"
export MESON_OPTS="--cross-file=/usr/share/mingw/toolchain-mingw64.meson"
