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
    dpkg --add-architecture armel
    apt-get update
    apt-get dist-upgrade -y
    apt-get install --no-install-recommends -y dpkg-dev
    apt-get install --no-install-recommends -y \
            gcc-arm-linux-gnueabi \
            libacl1-dev:armel \
            libapparmor-dev:armel \
            libattr1-dev:armel \
            libaudit-dev:armel \
            libblkid-dev:armel \
            libc6-dev:armel \
            libcap-ng-dev:armel \
            libcurl4-gnutls-dev:armel \
            libdevmapper-dev:armel \
            libfuse-dev:armel \
            libglib2.0-dev:armel \
            libglusterfs-dev:armel \
            libgnutls28-dev:armel \
            libiscsi-dev:armel \
            libnl-3-dev:armel \
            libnl-route-3-dev:armel \
            libnuma-dev:armel \
            libparted-dev:armel \
            libpcap0.8-dev:armel \
            libpciaccess-dev:armel \
            librbd-dev:armel \
            libreadline-dev:armel \
            libsanlock-dev:armel \
            libsasl2-dev:armel \
            libselinux1-dev:armel \
            libssh-gcrypt-dev:armel \
            libssh2-1-dev:armel \
            libtirpc-dev:armel \
            libudev-dev:armel \
            libxml2-dev:armel \
            libyajl-dev:armel \
            systemtap-sdt-dev:armel
    mkdir -p /usr/local/share/meson/cross
    printf "[binaries]\n\
c = '/usr/bin/arm-linux-gnueabi-gcc'\n\
ar = '/usr/bin/arm-linux-gnueabi-gcc-ar'\n\
strip = '/usr/bin/arm-linux-gnueabi-strip'\n\
pkgconfig = '/usr/bin/arm-linux-gnueabi-pkg-config'\n\
\n\
[host_machine]\n\
system = 'linux'\n\
cpu_family = 'arm'\n\
cpu = 'arm'\n\
endian = 'little'\n" > /usr/local/share/meson/cross/arm-linux-gnueabi
    dpkg-query --showformat '${Package}_${Version}_${Architecture}\n' --show > /packages.txt
    mkdir -p /usr/libexec/ccache-wrappers
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/arm-linux-gnueabi-cc
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/arm-linux-gnueabi-gcc
}

export CCACHE_WRAPPERSDIR="/usr/libexec/ccache-wrappers"
export LANG="en_US.UTF-8"
export MAKE="/usr/bin/make"
export NINJA="/usr/bin/ninja"
export PYTHON="/usr/bin/python3"

export ABI="arm-linux-gnueabi"
export MESON_OPTS="--cross-file=arm-linux-gnueabi"
