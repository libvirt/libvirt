FROM fedora:rawhide

RUN dnf update -y --nogpgcheck fedora-gpg-keys && \
    dnf update -y && \
    dnf install -y \
        augeas \
        autoconf \
        automake \
        bash \
        bash-completion \
        ca-certificates \
        ccache \
        chrony \
        clang \
        cppi \
        dnsmasq \
        dwarves \
        ebtables \
        firewalld-filesystem \
        gcc \
        gdb \
        gettext-devel \
        git \
        glibc-langpack-en \
        iproute \
        iproute-tc \
        iscsi-initiator-utils \
        kmod \
        libtool \
        libwsman-devel \
        libxml2 \
        libxslt \
        lsof \
        lvm2 \
        make \
        meson \
        net-tools \
        nfs-utils \
        ninja-build \
        numad \
        parted \
        patch \
        perl \
        perl-App-cpanminus \
        polkit \
        python3 \
        python3-docutils \
        python3-flake8 \
        python3-pip \
        python3-setuptools \
        python3-wheel \
        qemu-img \
        radvd \
        rpcgen \
        rpm-build \
        screen \
        scrub \
        sheepdog \
        strace \
        sudo \
        vim \
        xz \
        zfs-fuse && \
    dnf autoremove -y && \
    dnf clean all -y && \
    mkdir -p /usr/libexec/ccache-wrappers && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/x86_64-w64-mingw32-cc && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/x86_64-w64-mingw32-$(basename /usr/bin/gcc)

RUN dnf install -y \
        mingw64-curl \
        mingw64-dbus \
        mingw64-dlfcn \
        mingw64-gcc \
        mingw64-gettext \
        mingw64-glib2 \
        mingw64-gnutls \
        mingw64-headers \
        mingw64-libssh2 \
        mingw64-libxml2 \
        mingw64-pkg-config \
        mingw64-portablexdr \
        mingw64-readline && \
    dnf clean all -y

ENV LANG "en_US.UTF-8"

ENV MAKE "/usr/bin/make"
ENV NINJA "/usr/bin/ninja"
ENV PYTHON "/usr/bin/python3"

ENV CCACHE_WRAPPERSDIR "/usr/libexec/ccache-wrappers"

ENV ABI "x86_64-w64-mingw32"
ENV CONFIGURE_OPTS "--host=x86_64-w64-mingw32"
ENV MESON_OPTS "--cross-file=/usr/share/mingw/toolchain-mingw64.meson"
