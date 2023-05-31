# THIS FILE WAS AUTO-GENERATED
#
#  $ lcitool manifest ci/manifest.yml
#
# https://gitlab.com/libvirt/libvirt-ci

FROM docker.io/library/alpine:3.17

RUN apk update && \
    apk upgrade && \
    apk add \
        acl-dev \
        attr-dev \
        audit-dev \
        augeas \
        bash-completion \
        ca-certificates \
        ccache \
        ceph-dev \
        clang \
        curl-dev \
        cyrus-sasl-dev \
        diffutils \
        eudev-dev \
        fuse-dev \
        gcc \
        gettext \
        git \
        glib-dev \
        gnutls-dev \
        grep \
        iproute2 \
        iptables \
        kmod \
        libcap-ng-dev \
        libnl3-dev \
        libpcap-dev \
        libpciaccess-dev \
        libselinux-dev \
        libssh-dev \
        libssh2-dev \
        libtirpc-dev \
        libxml2-dev \
        libxml2-utils \
        libxslt \
        lvm2 \
        lvm2-dev \
        make \
        meson \
        musl-dev \
        netcf-dev \
        nfs-utils \
        numactl-dev \
        open-iscsi \
        parted-dev \
        perl \
        pkgconf \
        polkit \
        py3-docutils \
        py3-flake8 \
        python3 \
        qemu-img \
        readline-dev \
        rpcgen \
        samurai \
        sed \
        util-linux-dev \
        wireshark-dev \
        xen-dev \
        yajl-dev && \
    apk list | sort > /packages.txt && \
    mkdir -p /usr/libexec/ccache-wrappers && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/cc && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/clang && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/gcc

ENV CCACHE_WRAPPERSDIR "/usr/libexec/ccache-wrappers"
ENV LANG "en_US.UTF-8"
ENV MAKE "/usr/bin/make"
ENV NINJA "/usr/bin/ninja"
ENV PYTHON "/usr/bin/python3"
