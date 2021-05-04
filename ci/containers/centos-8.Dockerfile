# THIS FILE WAS AUTO-GENERATED
#
#  $ lcitool dockerfile centos-8 libvirt
#
# https://gitlab.com/libvirt/libvirt-ci/-/commit/1d4e10a04c6a0d29302003244a9dc4dc3c9d06f0

FROM docker.io/library/centos:8

RUN dnf update -y && \
    dnf install 'dnf-command(config-manager)' -y && \
    dnf config-manager --set-enabled -y powertools && \
    dnf install -y centos-release-advanced-virtualization && \
    dnf install -y epel-release && \
    dnf install -y \
        audit-libs-devel \
        augeas \
        avahi-devel \
        bash-completion \
        ca-certificates \
        ccache \
        clang \
        cpp \
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
        netcf-devel \
        nfs-utils \
        ninja-build \
        numactl-devel \
        numad \
        parted \
        parted-devel \
        perl \
        pkgconfig \
        polkit \
        python3 \
        python3-docutils \
        python3-flake8 \
        python3-pip \
        python3-setuptools \
        python3-wheel \
        qemu-img \
        radvd \
        readline-devel \
        rpcgen \
        rpm-build \
        sanlock-devel \
        scrub \
        sed \
        systemtap-sdt-devel \
        wireshark-devel \
        xfsprogs-devel \
        yajl-devel && \
    dnf autoremove -y && \
    dnf clean all -y && \
    rpm -qa | sort > /packages.txt && \
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
