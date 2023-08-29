# THIS FILE WAS AUTO-GENERATED
#
#  $ lcitool manifest ci/manifest.yml
#
# https://gitlab.com/libvirt/libvirt-ci

function install_buildenv() {
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get dist-upgrade -y
    apt-get install --no-install-recommends -y \
            augeas-lenses \
            augeas-tools \
            bash-completion \
            ca-certificates \
            ccache \
            codespell \
            cpp \
            diffutils \
            dwarves \
            ebtables \
            flake8 \
            gettext \
            git \
            grep \
            iproute2 \
            iptables \
            kmod \
            libc-dev-bin \
            libnbd-dev \
            libxml2-utils \
            locales \
            lvm2 \
            make \
            meson \
            nfs-common \
            ninja-build \
            numad \
            open-iscsi \
            perl-base \
            pkgconf \
            policykit-1 \
            python3 \
            python3-docutils \
            qemu-utils \
            scrub \
            sed \
            xsltproc
    sed -Ei 's,^# (en_US\.UTF-8 .*)$,\1,' /etc/locale.gen
    dpkg-reconfigure locales
    export DEBIAN_FRONTEND=noninteractive
    dpkg --add-architecture arm64
    apt-get update
    apt-get dist-upgrade -y
    apt-get install --no-install-recommends -y dpkg-dev
    apt-get install --no-install-recommends -y \
            gcc-aarch64-linux-gnu \
            libacl1-dev:arm64 \
            libapparmor-dev:arm64 \
            libattr1-dev:arm64 \
            libaudit-dev:arm64 \
            libblkid-dev:arm64 \
            libc6-dev:arm64 \
            libcap-ng-dev:arm64 \
            libcurl4-gnutls-dev:arm64 \
            libdevmapper-dev:arm64 \
            libfuse-dev:arm64 \
            libglib2.0-dev:arm64 \
            libglusterfs-dev:arm64 \
            libgnutls28-dev:arm64 \
            libiscsi-dev:arm64 \
            libnl-3-dev:arm64 \
            libnl-route-3-dev:arm64 \
            libnuma-dev:arm64 \
            libparted-dev:arm64 \
            libpcap0.8-dev:arm64 \
            libpciaccess-dev:arm64 \
            librbd-dev:arm64 \
            libreadline-dev:arm64 \
            libsanlock-dev:arm64 \
            libsasl2-dev:arm64 \
            libselinux1-dev:arm64 \
            libssh-gcrypt-dev:arm64 \
            libssh2-1-dev:arm64 \
            libtirpc-dev:arm64 \
            libudev-dev:arm64 \
            libxen-dev:arm64 \
            libxml2-dev:arm64 \
            libyajl-dev:arm64 \
            systemtap-sdt-dev:arm64
    mkdir -p /usr/local/share/meson/cross
    printf "[binaries]\n\
c = '/usr/bin/aarch64-linux-gnu-gcc'\n\
ar = '/usr/bin/aarch64-linux-gnu-gcc-ar'\n\
strip = '/usr/bin/aarch64-linux-gnu-strip'\n\
pkgconfig = '/usr/bin/aarch64-linux-gnu-pkg-config'\n\
\n\
[host_machine]\n\
system = 'linux'\n\
cpu_family = 'aarch64'\n\
cpu = 'aarch64'\n\
endian = 'little'\n" > /usr/local/share/meson/cross/aarch64-linux-gnu
    dpkg-query --showformat '${Package}_${Version}_${Architecture}\n' --show > /packages.txt
    mkdir -p /usr/libexec/ccache-wrappers
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/aarch64-linux-gnu-cc
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/aarch64-linux-gnu-gcc
}

export CCACHE_WRAPPERSDIR="/usr/libexec/ccache-wrappers"
export LANG="en_US.UTF-8"
export MAKE="/usr/bin/make"
export NINJA="/usr/bin/ninja"
export PYTHON="/usr/bin/python3"

export ABI="aarch64-linux-gnu"
export MESON_OPTS="--cross-file=aarch64-linux-gnu"
