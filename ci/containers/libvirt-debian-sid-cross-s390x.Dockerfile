FROM debian:sid

RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get install --no-install-recommends -y \
            augeas-lenses \
            augeas-tools \
            autoconf \
            automake \
            autopoint \
            bash \
            bash-completion \
            ca-certificates \
            ccache \
            chrony \
            clang \
            cpanminus \
            dnsmasq-base \
            dwarves \
            ebtables \
            flake8 \
            gcc \
            gdb \
            gettext \
            git \
            iproute2 \
            kmod \
            libc-dev-bin \
            libtool \
            libtool-bin \
            libxml2-utils \
            locales \
            lsof \
            lvm2 \
            make \
            meson \
            net-tools \
            nfs-common \
            ninja-build \
            numad \
            open-iscsi \
            parted \
            patch \
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
            screen \
            scrub \
            strace \
            sudo \
            vim \
            xsltproc \
            xz-utils \
            zfs-fuse && \
    apt-get autoremove -y && \
    apt-get autoclean -y && \
    sed -Ei 's,^# (en_US\.UTF-8 .*)$,\1,' /etc/locale.gen && \
    dpkg-reconfigure locales && \
    mkdir -p /usr/libexec/ccache-wrappers && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/s390x-linux-gnu-cc && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/s390x-linux-gnu-$(basename /usr/bin/gcc)

RUN export DEBIAN_FRONTEND=noninteractive && \
    dpkg --add-architecture s390x && \
    apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get install --no-install-recommends -y dpkg-dev && \
    apt-get install --no-install-recommends -y \
            gcc-s390x-linux-gnu \
            libacl1-dev:s390x \
            libapparmor-dev:s390x \
            libattr1-dev:s390x \
            libaudit-dev:s390x \
            libavahi-client-dev:s390x \
            libblkid-dev:s390x \
            libc6-dev:s390x \
            libcap-ng-dev:s390x \
            libcurl4-gnutls-dev:s390x \
            libdbus-1-dev:s390x \
            libdevmapper-dev:s390x \
            libfuse-dev:s390x \
            libglib2.0-dev:s390x \
            libglusterfs-dev:s390x \
            libgnutls28-dev:s390x \
            libiscsi-dev:s390x \
            libnl-3-dev:s390x \
            libnl-route-3-dev:s390x \
            libnuma-dev:s390x \
            libparted-dev:s390x \
            libpcap0.8-dev:s390x \
            libpciaccess-dev:s390x \
            librbd-dev:s390x \
            libreadline-dev:s390x \
            libsanlock-dev:s390x \
            libsasl2-dev:s390x \
            libselinux1-dev:s390x \
            libssh-gcrypt-dev:s390x \
            libssh2-1-dev:s390x \
            libtirpc-dev:s390x \
            libudev-dev:s390x \
            libxml2-dev:s390x \
            libyajl-dev:s390x \
            xfslibs-dev:s390x && \
    apt-get autoremove -y && \
    apt-get autoclean -y && \
    mkdir -p /usr/local/share/meson/cross && \
    echo "[binaries]\n\
c = '/usr/bin/s390x-linux-gnu-gcc'\n\
ar = '/usr/bin/s390x-linux-gnu-gcc-ar'\n\
strip = '/usr/bin/s390x-linux-gnu-strip'\n\
pkgconfig = '/usr/bin/s390x-linux-gnu-pkg-config'\n\
\n\
[host_machine]\n\
system = 'linux'\n\
cpu_family = 's390x'\n\
cpu = 's390x'\n\
endian = 'little'" > /usr/local/share/meson/cross/s390x-linux-gnu

ENV LANG "en_US.UTF-8"

ENV MAKE "/usr/bin/make"
ENV NINJA "/usr/bin/ninja"
ENV PYTHON "/usr/bin/python3"

ENV CCACHE_WRAPPERSDIR "/usr/libexec/ccache-wrappers"

ENV ABI "s390x-linux-gnu"
ENV CONFIGURE_OPTS "--host=s390x-linux-gnu"
ENV MESON_OPTS "--cross-file=s390x-linux-gnu"
