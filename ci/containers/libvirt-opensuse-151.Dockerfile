FROM opensuse/leap:15.1

RUN zypper update -y && \
    zypper install -y \
           audit-devel \
           augeas \
           augeas-lenses \
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
           dbus-1-devel \
           device-mapper-devel \
           dnsmasq \
           dwarves \
           ebtables \
           fuse-devel \
           gcc \
           gdb \
           gettext \
           gettext-devel \
           git \
           glib2-devel \
           glibc-devel \
           glibc-locale \
           glusterfs-devel \
           iproute2 \
           kmod \
           libacl-devel \
           libapparmor-devel \
           libattr-devel \
           libblkid-devel \
           libcap-ng-devel \
           libcurl-devel \
           libgnutls-devel \
           libiscsi-devel \
           libnl3-devel \
           libnuma-devel \
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
           libyajl-devel \
           lsof \
           lvm2 \
           make \
           net-tools \
           nfs-utils \
           ninja \
           numad \
           open-iscsi \
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
           qemu-tools \
           radvd \
           readline-devel \
           rpcgen \
           rpm-build \
           sanlock-devel \
           screen \
           scrub \
           strace \
           sudo \
           systemtap-sdt-devel \
           vim \
           wireshark-devel \
           xen-devel \
           xfsprogs-devel \
           xz && \
    zypper clean --all && \
    mkdir -p /usr/libexec/ccache-wrappers && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/cc && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/$(basename /usr/bin/gcc)

RUN pip3 install \
         meson==0.54.0

ENV LANG "en_US.UTF-8"

ENV MAKE "/usr/bin/make"
ENV NINJA "/usr/bin/ninja"
ENV PYTHON "/usr/bin/python3"

ENV CCACHE_WRAPPERSDIR "/usr/libexec/ccache-wrappers"
