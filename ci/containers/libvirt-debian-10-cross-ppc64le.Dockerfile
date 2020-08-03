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
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/powerpc64le-linux-gnu-cc && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/powerpc64le-linux-gnu-$(basename /usr/bin/gcc)

RUN export DEBIAN_FRONTEND=noninteractive && \
    dpkg --add-architecture ppc64el && \
    apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get install --no-install-recommends -y dpkg-dev && \
    apt-get install --no-install-recommends -y \
            gcc-powerpc64le-linux-gnu \
            libacl1-dev:ppc64el \
            libapparmor-dev:ppc64el \
            libattr1-dev:ppc64el \
            libaudit-dev:ppc64el \
            libavahi-client-dev:ppc64el \
            libblkid-dev:ppc64el \
            libc6-dev:ppc64el \
            libcap-ng-dev:ppc64el \
            libcurl4-gnutls-dev:ppc64el \
            libdbus-1-dev:ppc64el \
            libdevmapper-dev:ppc64el \
            libfuse-dev:ppc64el \
            libglib2.0-dev:ppc64el \
            libglusterfs-dev:ppc64el \
            libgnutls28-dev:ppc64el \
            libiscsi-dev:ppc64el \
            libnl-3-dev:ppc64el \
            libnl-route-3-dev:ppc64el \
            libnuma-dev:ppc64el \
            libparted-dev:ppc64el \
            libpcap0.8-dev:ppc64el \
            libpciaccess-dev:ppc64el \
            librbd-dev:ppc64el \
            libreadline-dev:ppc64el \
            libsanlock-dev:ppc64el \
            libsasl2-dev:ppc64el \
            libselinux1-dev:ppc64el \
            libssh-gcrypt-dev:ppc64el \
            libssh2-1-dev:ppc64el \
            libtirpc-dev:ppc64el \
            libudev-dev:ppc64el \
            libxml2-dev:ppc64el \
            libyajl-dev:ppc64el \
            xfslibs-dev:ppc64el && \
    apt-get autoremove -y && \
    apt-get autoclean -y && \
    mkdir -p /usr/local/share/meson/cross && \
    echo "[binaries]\n\
c = '/usr/bin/powerpc64le-linux-gnu-gcc'\n\
ar = '/usr/bin/powerpc64le-linux-gnu-gcc-ar'\n\
strip = '/usr/bin/powerpc64le-linux-gnu-strip'\n\
pkgconfig = '/usr/bin/powerpc64le-linux-gnu-pkg-config'\n\
\n\
[host_machine]\n\
system = 'linux'\n\
cpu_family = 'ppc64'\n\
cpu = 'powerpc64le'\n\
endian = 'little'" > /usr/local/share/meson/cross/powerpc64le-linux-gnu

RUN pip3 install \
         meson==0.54.0

ENV LANG "en_US.UTF-8"

ENV MAKE "/usr/bin/make"
ENV NINJA "/usr/bin/ninja"
ENV PYTHON "/usr/bin/python3"

ENV CCACHE_WRAPPERSDIR "/usr/libexec/ccache-wrappers"

ENV ABI "powerpc64le-linux-gnu"
ENV CONFIGURE_OPTS "--host=powerpc64le-linux-gnu"
ENV MESON_OPTS "--cross-file=powerpc64le-linux-gnu"
