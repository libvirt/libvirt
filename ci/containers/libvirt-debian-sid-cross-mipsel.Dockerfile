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
            zfs-fuse && \
    apt-get autoremove -y && \
    apt-get autoclean -y && \
    sed -Ei 's,^# (en_US\.UTF-8 .*)$,\1,' /etc/locale.gen && \
    dpkg-reconfigure locales && \
    mkdir -p /usr/libexec/ccache-wrappers && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/mipsel-linux-gnu-cc && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/mipsel-linux-gnu-$(basename /usr/bin/gcc)

RUN export DEBIAN_FRONTEND=noninteractive && \
    dpkg --add-architecture mipsel && \
    apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get install --no-install-recommends -y dpkg-dev && \
    apt-get install --no-install-recommends -y \
            gcc-mipsel-linux-gnu \
            libacl1-dev:mipsel \
            libapparmor-dev:mipsel \
            libattr1-dev:mipsel \
            libaudit-dev:mipsel \
            libavahi-client-dev:mipsel \
            libblkid-dev:mipsel \
            libc6-dev:mipsel \
            libcap-ng-dev:mipsel \
            libcurl4-gnutls-dev:mipsel \
            libdbus-1-dev:mipsel \
            libdevmapper-dev:mipsel \
            libfuse-dev:mipsel \
            libglib2.0-dev:mipsel \
            libglusterfs-dev:mipsel \
            libgnutls28-dev:mipsel \
            libiscsi-dev:mipsel \
            libncurses-dev:mipsel \
            libnl-3-dev:mipsel \
            libnl-route-3-dev:mipsel \
            libnuma-dev:mipsel \
            libparted-dev:mipsel \
            libpcap0.8-dev:mipsel \
            libpciaccess-dev:mipsel \
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
            xfslibs-dev:mipsel && \
    apt-get autoremove -y && \
    apt-get autoclean -y

ENV LANG "en_US.UTF-8"

ENV MAKE "/usr/bin/make"
ENV NINJA "/usr/bin/ninja"
ENV PYTHON "/usr/bin/python3"

ENV CCACHE_WRAPPERSDIR "/usr/libexec/ccache-wrappers"

ENV ABI "mipsel-linux-gnu"
ENV CONFIGURE_OPTS "--host=mipsel-linux-gnu"
