# THIS FILE WAS AUTO-GENERATED
#
#  $ lcitool manifest ci/manifest.yml
#
# https://gitlab.com/libvirt/libvirt-ci

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
            xsltproc && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y && \
    sed -Ei 's,^# (en_US\.UTF-8 .*)$,\1,' /etc/locale.gen && \
    dpkg-reconfigure locales

RUN export DEBIAN_FRONTEND=noninteractive && \
    dpkg --add-architecture i386 && \
    eatmydata apt-get update && \
    eatmydata apt-get dist-upgrade -y && \
    eatmydata apt-get install --no-install-recommends -y dpkg-dev && \
    eatmydata apt-get install --no-install-recommends -y \
            gcc-i686-linux-gnu \
            libacl1-dev:i386 \
            libapparmor-dev:i386 \
            libattr1-dev:i386 \
            libaudit-dev:i386 \
            libblkid-dev:i386 \
            libc6-dev:i386 \
            libcap-ng-dev:i386 \
            libcurl4-gnutls-dev:i386 \
            libdbus-1-dev:i386 \
            libdevmapper-dev:i386 \
            libfuse-dev:i386 \
            libglib2.0-dev:i386 \
            libglusterfs-dev:i386 \
            libgnutls28-dev:i386 \
            libiscsi-dev:i386 \
            libnl-3-dev:i386 \
            libnl-route-3-dev:i386 \
            libnuma-dev:i386 \
            libparted-dev:i386 \
            libpcap0.8-dev:i386 \
            libpciaccess-dev:i386 \
            librbd-dev:i386 \
            libreadline-dev:i386 \
            libsanlock-dev:i386 \
            libsasl2-dev:i386 \
            libselinux1-dev:i386 \
            libssh-gcrypt-dev:i386 \
            libssh2-1-dev:i386 \
            libtirpc-dev:i386 \
            libudev-dev:i386 \
            libxml2-dev:i386 \
            libyajl-dev:i386 \
            systemtap-sdt-dev:i386 \
            xfslibs-dev:i386 && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y && \
    mkdir -p /usr/local/share/meson/cross && \
    echo "[binaries]\n\
c = '/usr/bin/i686-linux-gnu-gcc'\n\
ar = '/usr/bin/i686-linux-gnu-gcc-ar'\n\
strip = '/usr/bin/i686-linux-gnu-strip'\n\
pkgconfig = '/usr/bin/i686-linux-gnu-pkg-config'\n\
\n\
[host_machine]\n\
system = 'linux'\n\
cpu_family = 'x86'\n\
cpu = 'i686'\n\
endian = 'little'" > /usr/local/share/meson/cross/i686-linux-gnu && \
    dpkg-query --showformat '${Package}_${Version}_${Architecture}\n' --show > /packages.txt && \
    mkdir -p /usr/libexec/ccache-wrappers && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/i686-linux-gnu-cc && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/i686-linux-gnu-gcc

RUN pip3 install \
         meson==0.56.0

ENV LANG "en_US.UTF-8"
ENV MAKE "/usr/bin/make"
ENV NINJA "/usr/bin/ninja"
ENV PYTHON "/usr/bin/python3"
ENV CCACHE_WRAPPERSDIR "/usr/libexec/ccache-wrappers"

ENV ABI "i686-linux-gnu"
ENV MESON_OPTS "--cross-file=i686-linux-gnu"
