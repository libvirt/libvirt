# THIS FILE WAS AUTO-GENERATED
#
#  $ lcitool manifest ci/manifest.yml
#
# https://gitlab.com/libvirt/libvirt-ci

function install_buildenv() {
    dnf distro-sync -y
    dnf install 'dnf-command(config-manager)' -y
    dnf config-manager --set-enabled -y powertools
    dnf install -y centos-release-advanced-virtualization
    dnf install -y epel-release
    dnf install -y epel-next-release
    dnf install -y \
        audit-libs-devel \
        augeas \
        bash-completion \
        ca-certificates \
        ccache \
        clang \
        cpp \
        cyrus-sasl-devel \
        device-mapper-devel \
        diffutils \
        dwarves \
        ebtables \
        firewalld-filesystem \
        fuse-devel \
        gcc \
        gettext \
        git \
        glib2-devel \
        glibc-devel \
        glibc-langpack-en \
        glusterfs-api-devel \
        gnutls-devel \
        grep \
        iproute \
        iproute-tc \
        iptables \
        iscsi-initiator-utils \
        kmod \
        libacl-devel \
        libattr-devel \
        libblkid-devel \
        libcap-ng-devel \
        libcurl-devel \
        libiscsi-devel \
        libnbd-devel \
        libnl3-devel \
        libpcap-devel \
        libpciaccess-devel \
        librbd-devel \
        libselinux-devel \
        libssh-devel \
        libssh2-devel \
        libtirpc-devel \
        libwsman-devel \
        libxml2 \
        libxml2-devel \
        libxslt \
        lvm2 \
        make \
        meson \
        netcf-devel \
        nfs-utils \
        ninja-build \
        numactl-devel \
        numad \
        parted-devel \
        perl \
        pkgconfig \
        polkit \
        python3 \
        python3-docutils \
        python3-flake8 \
        qemu-img \
        readline-devel \
        rpcgen \
        rpm-build \
        sanlock-devel \
        scrub \
        sed \
        systemd-devel \
        systemd-rpm-macros \
        systemtap-sdt-devel \
        wireshark-devel \
        yajl-devel
    rpm -qa | sort > /packages.txt
    mkdir -p /usr/libexec/ccache-wrappers
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/cc
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/clang
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/gcc
}

export CCACHE_WRAPPERSDIR="/usr/libexec/ccache-wrappers"
export LANG="en_US.UTF-8"
export MAKE="/usr/bin/make"
export NINJA="/usr/bin/ninja"
export PYTHON="/usr/bin/python3"
