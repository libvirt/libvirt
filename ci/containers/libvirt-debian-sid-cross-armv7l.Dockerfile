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
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/arm-linux-gnueabihf-cc && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/arm-linux-gnueabihf-$(basename /usr/bin/gcc)

RUN export DEBIAN_FRONTEND=noninteractive && \
    dpkg --add-architecture armhf && \
    apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get install --no-install-recommends -y dpkg-dev && \
    apt-get install --no-install-recommends -y \
            gcc-arm-linux-gnueabihf \
            libacl1-dev:armhf \
            libapparmor-dev:armhf \
            libattr1-dev:armhf \
            libaudit-dev:armhf \
            libavahi-client-dev:armhf \
            libblkid-dev:armhf \
            libc6-dev:armhf \
            libcap-ng-dev:armhf \
            libcurl4-gnutls-dev:armhf \
            libdbus-1-dev:armhf \
            libdevmapper-dev:armhf \
            libfuse-dev:armhf \
            libglib2.0-dev:armhf \
            libglusterfs-dev:armhf \
            libgnutls28-dev:armhf \
            libiscsi-dev:armhf \
            libncurses-dev:armhf \
            libnl-3-dev:armhf \
            libnl-route-3-dev:armhf \
            libparted-dev:armhf \
            libpcap0.8-dev:armhf \
            libpciaccess-dev:armhf \
            librbd-dev:armhf \
            libreadline-dev:armhf \
            libsanlock-dev:armhf \
            libsasl2-dev:armhf \
            libselinux1-dev:armhf \
            libssh-gcrypt-dev:armhf \
            libssh2-1-dev:armhf \
            libtirpc-dev:armhf \
            libudev-dev:armhf \
            libxen-dev:armhf \
            libxml2-dev:armhf \
            libyajl-dev:armhf \
            xfslibs-dev:armhf && \
    apt-get autoremove -y && \
    apt-get autoclean -y

ENV LANG "en_US.UTF-8"

ENV MAKE "/usr/bin/make"
ENV NINJA "/usr/bin/ninja"
ENV PYTHON "/usr/bin/python3"

ENV CCACHE_WRAPPERSDIR "/usr/libexec/ccache-wrappers"

ENV ABI "arm-linux-gnueabihf"
ENV CONFIGURE_OPTS "--host=arm-linux-gnueabihf"
