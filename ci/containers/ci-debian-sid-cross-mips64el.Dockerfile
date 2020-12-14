# THIS FILE WAS AUTO-GENERATED
#
#  $ lcitool dockerfile --cross mips64el debian-sid libvirt
#
# https://gitlab.com/libvirt/libvirt-ci/-/commit/b098ec6631a85880f818f2dd25c437d509e53680
FROM docker.io/library/debian:sid-slim

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
            meson \
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
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/mips64el-linux-gnuabi64-cc && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/mips64el-linux-gnuabi64-$(basename /usr/bin/gcc)

RUN export DEBIAN_FRONTEND=noninteractive && \
    dpkg --add-architecture mips64el && \
    eatmydata apt-get update && \
    eatmydata apt-get dist-upgrade -y && \
    eatmydata apt-get install --no-install-recommends -y dpkg-dev && \
    eatmydata apt-get install --no-install-recommends -y \
            gcc-mips64el-linux-gnuabi64 \
            libacl1-dev:mips64el \
            libapparmor-dev:mips64el \
            libattr1-dev:mips64el \
            libaudit-dev:mips64el \
            libavahi-client-dev:mips64el \
            libblkid-dev:mips64el \
            libc6-dev:mips64el \
            libcap-ng-dev:mips64el \
            libcurl4-gnutls-dev:mips64el \
            libdbus-1-dev:mips64el \
            libdevmapper-dev:mips64el \
            libfuse-dev:mips64el \
            libglib2.0-dev:mips64el \
            libglusterfs-dev:mips64el \
            libgnutls28-dev:mips64el \
            libiscsi-dev:mips64el \
            libnl-3-dev:mips64el \
            libnl-route-3-dev:mips64el \
            libnuma-dev:mips64el \
            libparted-dev:mips64el \
            libpcap0.8-dev:mips64el \
            libpciaccess-dev:mips64el \
            librbd-dev:mips64el \
            libreadline-dev:mips64el \
            libsanlock-dev:mips64el \
            libsasl2-dev:mips64el \
            libselinux1-dev:mips64el \
            libssh-gcrypt-dev:mips64el \
            libssh2-1-dev:mips64el \
            libtirpc-dev:mips64el \
            libudev-dev:mips64el \
            libxml2-dev:mips64el \
            libyajl-dev:mips64el \
            xfslibs-dev:mips64el && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y && \
    mkdir -p /usr/local/share/meson/cross && \
    echo "[binaries]\n\
c = '/usr/bin/mips64el-linux-gnuabi64-gcc'\n\
ar = '/usr/bin/mips64el-linux-gnuabi64-gcc-ar'\n\
strip = '/usr/bin/mips64el-linux-gnuabi64-strip'\n\
pkgconfig = '/usr/bin/mips64el-linux-gnuabi64-pkg-config'\n\
\n\
[host_machine]\n\
system = 'linux'\n\
cpu_family = 'mips64'\n\
cpu = 'mips64el'\n\
endian = 'little'" > /usr/local/share/meson/cross/mips64el-linux-gnuabi64

ENV LANG "en_US.UTF-8"
ENV MAKE "/usr/bin/make"
ENV NINJA "/usr/bin/ninja"
ENV PYTHON "/usr/bin/python3"
ENV CCACHE_WRAPPERSDIR "/usr/libexec/ccache-wrappers"

ENV ABI "mips64el-linux-gnuabi64"
ENV MESON_OPTS "--cross-file=mips64el-linux-gnuabi64"
