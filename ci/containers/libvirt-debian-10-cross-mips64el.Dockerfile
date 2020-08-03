FROM debian:10

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
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/mips64el-linux-gnuabi64-cc && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/mips64el-linux-gnuabi64-$(basename /usr/bin/gcc)

RUN export DEBIAN_FRONTEND=noninteractive && \
    dpkg --add-architecture mips64el && \
    apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get install --no-install-recommends -y dpkg-dev && \
    apt-get install --no-install-recommends -y \
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
    apt-get autoremove -y && \
    apt-get autoclean -y && \
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

RUN pip3 install \
         meson==0.54.0

ENV LANG "en_US.UTF-8"

ENV MAKE "/usr/bin/make"
ENV NINJA "/usr/bin/ninja"
ENV PYTHON "/usr/bin/python3"

ENV CCACHE_WRAPPERSDIR "/usr/libexec/ccache-wrappers"

ENV ABI "mips64el-linux-gnuabi64"
ENV CONFIGURE_OPTS "--host=mips64el-linux-gnuabi64"
ENV MESON_OPTS "--cross-file=mips64el-linux-gnuabi64"
