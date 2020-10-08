FROM fedora:rawhide

RUN dnf update -y --nogpgcheck fedora-gpg-keys && \
    dnf update -y && \
    dnf install -y \
        audit-libs-devel \
        augeas \
        autoconf \
        automake \
        avahi-devel \
        bash \
        bash-completion \
        ca-certificates \
        ccache \
        chrony \
        clang \
        cppi \
        cyrus-sasl-devel \
        dbus-devel \
        device-mapper-devel \
        dnsmasq \
        dwarves \
        ebtables \
        firewalld-filesystem \
        fuse-devel \
        gcc \
        gdb \
        gettext \
        gettext-devel \
        git \
        glib2-devel \
        glibc-devel \
        glibc-langpack-en \
        glusterfs-api-devel \
        gnutls-devel \
        iproute \
        iproute-tc \
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
        libtool \
        libudev-devel \
        libwsman-devel \
        libxml2 \
        libxml2-devel \
        libxslt \
        lsof \
        lvm2 \
        make \
        meson \
        net-tools \
        netcf-devel \
        nfs-utils \
        ninja-build \
        numactl-devel \
        numad \
        parted \
        parted-devel \
        patch \
        perl \
        perl-App-cpanminus \
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
        screen \
        scrub \
        sheepdog \
        strace \
        sudo \
        systemtap-sdt-devel \
        vim \
        wireshark-devel \
        xen-devel \
        xfsprogs-devel \
        xz \
        yajl-devel \
        zfs-fuse && \
    dnf autoremove -y && \
    dnf clean all -y && \
    mkdir -p /usr/libexec/ccache-wrappers && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/cc && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/$(basename /usr/bin/gcc)

ENV LANG "en_US.UTF-8"

ENV MAKE "/usr/bin/make"
ENV NINJA "/usr/bin/ninja"
ENV PYTHON "/usr/bin/python3"

ENV CCACHE_WRAPPERSDIR "/usr/libexec/ccache-wrappers"
