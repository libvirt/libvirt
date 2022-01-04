# THIS FILE WAS AUTO-GENERATED
#
#  $ lcitool manifest ci/manifest.yml
#
# https://gitlab.com/libvirt/libvirt-ci

FROM docker.io/library/ubuntu:18.04

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
            codespell \
            cpp \
            diffutils \
            dnsmasq-base \
            dwarves \
            ebtables \
            flake8 \
            gcc \
            gettext \
            git \
            glusterfs-common \
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
            libdevmapper-dev \
            libfuse-dev \
            libglib2.0-dev \
            libgnutls28-dev \
            libiscsi-dev \
            libnetcf-dev \
            libnl-3-dev \
            libnl-route-3-dev \
            libnuma-dev \
            libopenwsman-dev \
            libparted-dev \
            libpcap0.8-dev \
            libpciaccess-dev \
            librbd-dev \
            libreadline-dev \
            libsanlock-dev \
            libsasl2-dev \
            libselinux1-dev \
            libssh-dev \
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
            nfs-common \
            ninja-build \
            numad \
            open-iscsi \
            perl-base \
            pkgconf \
            policykit-1 \
            python3 \
            python3-docutils \
            python3-pip \
            python3-setuptools \
            python3-wheel \
            qemu-utils \
            scrub \
            sed \
            sheepdog \
            systemtap-sdt-dev \
            wireshark-dev \
            xsltproc && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y && \
    sed -Ei 's,^# (en_US\.UTF-8 .*)$,\1,' /etc/locale.gen && \
    dpkg-reconfigure locales && \
    dpkg-query --showformat '${Package}_${Version}_${Architecture}\n' --show > /packages.txt && \
    mkdir -p /usr/libexec/ccache-wrappers && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/cc && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/clang && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/gcc

RUN pip3 install \
         meson==0.56.0

ENV LANG "en_US.UTF-8"
ENV MAKE "/usr/bin/make"
ENV NINJA "/usr/bin/ninja"
ENV PYTHON "/usr/bin/python3"
ENV CCACHE_WRAPPERSDIR "/usr/libexec/ccache-wrappers"
