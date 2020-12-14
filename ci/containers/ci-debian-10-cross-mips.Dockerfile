# THIS FILE WAS AUTO-GENERATED
#
#  $ lcitool dockerfile --cross mips debian-10 libvirt
#
# https://gitlab.com/libvirt/libvirt-ci/-/commit/b098ec6631a85880f818f2dd25c437d509e53680
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
            clang \
            diffutils \
            dnsmasq-base \
            dwarves \
            ebtables \
            flake8 \
            gcc \
            gettext \
            git \
            iproute2 \
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
            perl \
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
            xsltproc \
            zfs-fuse && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y && \
    sed -Ei 's,^# (en_US\.UTF-8 .*)$,\1,' /etc/locale.gen && \
    dpkg-reconfigure locales && \
    dpkg-query --showformat '${Package}_${Version}_${Architecture}\n' --show > /packages.txt && \
    mkdir -p /usr/libexec/ccache-wrappers && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/mips-linux-gnu-cc && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/mips-linux-gnu-$(basename /usr/bin/gcc)

RUN export DEBIAN_FRONTEND=noninteractive && \
    dpkg --add-architecture mips && \
    eatmydata apt-get update && \
    eatmydata apt-get dist-upgrade -y && \
    eatmydata apt-get install --no-install-recommends -y dpkg-dev && \
    eatmydata apt-get install --no-install-recommends -y \
            gcc-mips-linux-gnu \
            libacl1-dev:mips \
            libapparmor-dev:mips \
            libattr1-dev:mips \
            libaudit-dev:mips \
            libavahi-client-dev:mips \
            libblkid-dev:mips \
            libc6-dev:mips \
            libcap-ng-dev:mips \
            libcurl4-gnutls-dev:mips \
            libdbus-1-dev:mips \
            libdevmapper-dev:mips \
            libfuse-dev:mips \
            libglib2.0-dev:mips \
            libglusterfs-dev:mips \
            libgnutls28-dev:mips \
            libiscsi-dev:mips \
            libnl-3-dev:mips \
            libnl-route-3-dev:mips \
            libnuma-dev:mips \
            libparted-dev:mips \
            libpcap0.8-dev:mips \
            libpciaccess-dev:mips \
            librbd-dev:mips \
            libreadline-dev:mips \
            libsanlock-dev:mips \
            libsasl2-dev:mips \
            libselinux1-dev:mips \
            libssh-gcrypt-dev:mips \
            libssh2-1-dev:mips \
            libtirpc-dev:mips \
            libudev-dev:mips \
            libxml2-dev:mips \
            libyajl-dev:mips \
            xfslibs-dev:mips && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y && \
    mkdir -p /usr/local/share/meson/cross && \
    echo "[binaries]\n\
c = '/usr/bin/mips-linux-gnu-gcc'\n\
ar = '/usr/bin/mips-linux-gnu-gcc-ar'\n\
strip = '/usr/bin/mips-linux-gnu-strip'\n\
pkgconfig = '/usr/bin/mips-linux-gnu-pkg-config'\n\
\n\
[host_machine]\n\
system = 'linux'\n\
cpu_family = 'mips'\n\
cpu = 'mips'\n\
endian = 'little'" > /usr/local/share/meson/cross/mips-linux-gnu

RUN pip3 install \
         meson==0.54.0

ENV LANG "en_US.UTF-8"
ENV MAKE "/usr/bin/make"
ENV NINJA "/usr/bin/ninja"
ENV PYTHON "/usr/bin/python3"
ENV CCACHE_WRAPPERSDIR "/usr/libexec/ccache-wrappers"

ENV ABI "mips-linux-gnu"
ENV MESON_OPTS "--cross-file=mips-linux-gnu"
