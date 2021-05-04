# THIS FILE WAS AUTO-GENERATED
#
#  $ lcitool dockerfile fedora-34 libvirt
#
# https://gitlab.com/libvirt/libvirt-ci/-/commit/1d4e10a04c6a0d29302003244a9dc4dc3c9d06f0

FROM registry.fedoraproject.org/fedora:34

RUN dnf install -y nosync && \
    echo -e '#!/bin/sh\n\
if test -d /usr/lib64\n\
then\n\
    export LD_PRELOAD=/usr/lib64/nosync/nosync.so\n\
else\n\
    export LD_PRELOAD=/usr/lib/nosync/nosync.so\n\
fi\n\
exec "$@"' > /usr/bin/nosync && \
    chmod +x /usr/bin/nosync && \
    nosync dnf update -y && \
    nosync dnf install -y \
        audit-libs-devel \
        augeas \
        avahi-devel \
        bash-completion \
        ca-certificates \
        ccache \
        clang \
        cpp \
        cppi \
        cyrus-sasl-devel \
        dbus-devel \
        device-mapper-devel \
        diffutils \
        dnsmasq \
        dwarves \
        ebtables \
        firewalld-filesystem \
        fuse-devel \
        gcc \
        gettext \
        git \
        glib2-devel \
        glibc-devel \
        glibc-langpack-en \
        glusterfs-api-devel \
        gnutls-devel \
        grep \
        iproute \
        iproute-tc \
        iptables \
        iscsi-initiator-utils \
        kmod \
        libacl-devel \
        libattr-devel \
        libblkid-devel \
        libcap-ng-devel \
        libcurl-devel \
        libiscsi-devel \
        libnl3-devel \
        libpcap-devel \
        libpciaccess-devel \
        librbd-devel \
        libselinux-devel \
        libssh-devel \
        libssh2-devel \
        libtirpc-devel \
        libudev-devel \
        libwsman-devel \
        libxml2 \
        libxml2-devel \
        libxslt \
        lvm2 \
        make \
        meson \
        netcf-devel \
        nfs-utils \
        ninja-build \
        numactl-devel \
        numad \
        parted \
        parted-devel \
        perl-base \
        pkgconfig \
        polkit \
        python3 \
        python3-docutils \
        python3-flake8 \
        qemu-img \
        radvd \
        readline-devel \
        rpcgen \
        rpm-build \
        sanlock-devel \
        scrub \
        sed \
        sheepdog \
        systemtap-sdt-devel \
        wireshark-devel \
        xen-devel \
        xfsprogs-devel \
        yajl-devel \
        zfs-fuse && \
    nosync dnf autoremove -y && \
    nosync dnf clean all -y && \
    rpm -qa | sort > /packages.txt && \
    mkdir -p /usr/libexec/ccache-wrappers && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/cc && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/clang && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/gcc

ENV LANG "en_US.UTF-8"
ENV MAKE "/usr/bin/make"
ENV NINJA "/usr/bin/ninja"
ENV PYTHON "/usr/bin/python3"
ENV CCACHE_WRAPPERSDIR "/usr/libexec/ccache-wrappers"
