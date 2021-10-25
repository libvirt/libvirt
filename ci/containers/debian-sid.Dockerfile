# THIS FILE WAS AUTO-GENERATED
#
#  $ lcitool manifest ci/manifest.yml
#
# https://gitlab.com/libvirt/libvirt-ci

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
            cpp \
            diffutils \
            dnsmasq-base \
            dwarves \
            ebtables \
            flake8 \
            gcc \
            gettext \
            git \
            grep \
            iproute2 \
            iptables \
            kmod \
            libacl1-dev \
            libapparmor-dev \
            libattr1-dev \
            libaudit-dev \
            libblkid-dev \
            libc-dev-bin \
            libc6-dev \
            libcap-ng-dev \
            libcurl4-gnutls-dev \
            libdbus-1-dev \
            libdevmapper-dev \
            libfuse-dev \
            libglib2.0-dev \
            libglusterfs-dev \
            libgnutls28-dev \
            libiscsi-dev \
            libnl-3-dev \
            libnl-route-3-dev \
            libnuma-dev \
            libparted-dev \
            libpcap0.8-dev \
            libpciaccess-dev \
            librbd-dev \
            libreadline-dev \
            libsanlock-dev \
            libsasl2-dev \
            libselinux1-dev \
            libssh-gcrypt-dev \
            libssh2-1-dev \
            libtirpc-dev \
            libudev-dev \
            libxen-dev \
            libxml2-dev \
            libxml2-utils \
            libyajl-dev \
            locales \
            lvm2 \
            make \
            meson \
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
            qemu-utils \
            radvd \
            scrub \
            sed \
            systemtap-sdt-dev \
            wireshark-dev \
            xfslibs-dev \
            xsltproc \
            zfs-fuse && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y && \
    sed -Ei 's,^# (en_US\.UTF-8 .*)$,\1,' /etc/locale.gen && \
    dpkg-reconfigure locales && \
    dpkg-query --showformat '${Package}_${Version}_${Architecture}\n' --show > /packages.txt && \
    mkdir -p /usr/libexec/ccache-wrappers && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/cc && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/clang && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/gcc

ENV LANG "en_US.UTF-8"
ENV MAKE "/usr/bin/make"
ENV NINJA "/usr/bin/ninja"
ENV PYTHON "/usr/bin/python3"
ENV CCACHE_WRAPPERSDIR "/usr/libexec/ccache-wrappers"
