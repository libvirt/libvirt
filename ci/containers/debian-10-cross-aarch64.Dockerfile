# THIS FILE WAS AUTO-GENERATED
#
#  $ lcitool dockerfile --cross aarch64 debian-10 libvirt
#
# https://gitlab.com/libvirt/libvirt-ci/-/commit/1d4e10a04c6a0d29302003244a9dc4dc3c9d06f0

FROM docker.io/library/debian:10-slim

RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -y eatmydata && \
    eatmydata apt-get dist-upgrade -y && \
    eatmydata apt-get install --no-install-recommends -y \
            augeas-lenses \
            augeas-tools \
            bash-completion \
            ca-certificates \
            ccache \
            cpp \
            diffutils \
            dnsmasq-base \
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
            nfs-common \
            ninja-build \
            numad \
            open-iscsi \
            parted \
            perl-base \
            pkgconf \
            policykit-1 \
            python3 \
            python3-docutils \
            python3-pip \
            python3-setuptools \
            python3-wheel \
            qemu-utils \
            radvd \
            scrub \
            sed \
            xsltproc \
            zfs-fuse && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y && \
    sed -Ei 's,^# (en_US\.UTF-8 .*)$,\1,' /etc/locale.gen && \
    dpkg-reconfigure locales && \
    dpkg-query --showformat '${Package}_${Version}_${Architecture}\n' --show > /packages.txt && \
    mkdir -p /usr/libexec/ccache-wrappers && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/aarch64-linux-gnu-cc && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/aarch64-linux-gnu-gcc

RUN export DEBIAN_FRONTEND=noninteractive && \
    dpkg --add-architecture arm64 && \
    eatmydata apt-get update && \
    eatmydata apt-get dist-upgrade -y && \
    eatmydata apt-get install --no-install-recommends -y dpkg-dev && \
    eatmydata apt-get install --no-install-recommends -y \
            gcc-aarch64-linux-gnu \
            libacl1-dev:arm64 \
            libapparmor-dev:arm64 \
            libattr1-dev:arm64 \
            libaudit-dev:arm64 \
            libavahi-client-dev:arm64 \
            libblkid-dev:arm64 \
            libc6-dev:arm64 \
            libcap-ng-dev:arm64 \
            libcurl4-gnutls-dev:arm64 \
            libdbus-1-dev:arm64 \
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
            systemtap-sdt-dev:arm64 \
            xfslibs-dev:arm64 && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y && \
    mkdir -p /usr/local/share/meson/cross && \
    echo "[binaries]\n\
c = '/usr/bin/aarch64-linux-gnu-gcc'\n\
ar = '/usr/bin/aarch64-linux-gnu-gcc-ar'\n\
strip = '/usr/bin/aarch64-linux-gnu-strip'\n\
pkgconfig = '/usr/bin/aarch64-linux-gnu-pkg-config'\n\
\n\
[host_machine]\n\
system = 'linux'\n\
cpu_family = 'aarch64'\n\
cpu = 'aarch64'\n\
endian = 'little'" > /usr/local/share/meson/cross/aarch64-linux-gnu

RUN pip3 install \
         meson==0.56.0

ENV LANG "en_US.UTF-8"
ENV MAKE "/usr/bin/make"
ENV NINJA "/usr/bin/ninja"
ENV PYTHON "/usr/bin/python3"
ENV CCACHE_WRAPPERSDIR "/usr/libexec/ccache-wrappers"

ENV ABI "aarch64-linux-gnu"
ENV MESON_OPTS "--cross-file=aarch64-linux-gnu"
