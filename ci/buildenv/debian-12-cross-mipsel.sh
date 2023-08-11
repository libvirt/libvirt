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
    dpkg --add-architecture mipsel
    apt-get update
    apt-get dist-upgrade -y
    apt-get install --no-install-recommends -y dpkg-dev
    apt-get install --no-install-recommends -y \
            gcc-mipsel-linux-gnu \
            libacl1-dev:mipsel \
            libapparmor-dev:mipsel \
            libattr1-dev:mipsel \
            libaudit-dev:mipsel \
            libblkid-dev:mipsel \
            libc6-dev:mipsel \
            libcap-ng-dev:mipsel \
            libcurl4-gnutls-dev:mipsel \
            libdevmapper-dev:mipsel \
            libfuse-dev:mipsel \
            libglib2.0-dev:mipsel \
            libglusterfs-dev:mipsel \
            libgnutls28-dev:mipsel \
            libiscsi-dev:mipsel \
            libnl-3-dev:mipsel \
            libnl-route-3-dev:mipsel \
            libnuma-dev:mipsel \
            libparted-dev:mipsel \
            libpcap0.8-dev:mipsel \
            libpciaccess-dev:mipsel \
            librbd-dev:mipsel \
            libreadline-dev:mipsel \
            libsanlock-dev:mipsel \
            libsasl2-dev:mipsel \
            libselinux1-dev:mipsel \
            libssh-gcrypt-dev:mipsel \
            libssh2-1-dev:mipsel \
            libtirpc-dev:mipsel \
            libudev-dev:mipsel \
            libxml2-dev:mipsel \
            libyajl-dev:mipsel \
            systemtap-sdt-dev:mipsel
    mkdir -p /usr/local/share/meson/cross
    printf "[binaries]\n\
c = '/usr/bin/mipsel-linux-gnu-gcc'\n\
ar = '/usr/bin/mipsel-linux-gnu-gcc-ar'\n\
strip = '/usr/bin/mipsel-linux-gnu-strip'\n\
pkgconfig = '/usr/bin/mipsel-linux-gnu-pkg-config'\n\
\n\
[host_machine]\n\
system = 'linux'\n\
cpu_family = 'mips'\n\
cpu = 'mipsel'\n\
endian = 'little'\n" > /usr/local/share/meson/cross/mipsel-linux-gnu
    dpkg-query --showformat '${Package}_${Version}_${Architecture}\n' --show > /packages.txt
    mkdir -p /usr/libexec/ccache-wrappers
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/mipsel-linux-gnu-cc
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/mipsel-linux-gnu-gcc
}

export CCACHE_WRAPPERSDIR="/usr/libexec/ccache-wrappers"
export LANG="en_US.UTF-8"
export MAKE="/usr/bin/make"
export NINJA="/usr/bin/ninja"
export PYTHON="/usr/bin/python3"

export ABI="mipsel-linux-gnu"
export MESON_OPTS="--cross-file=mipsel-linux-gnu"
