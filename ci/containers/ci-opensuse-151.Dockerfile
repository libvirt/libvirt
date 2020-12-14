# THIS FILE WAS AUTO-GENERATED
#
#  $ lcitool dockerfile opensuse-151 libvirt
#
# https://gitlab.com/libvirt/libvirt-ci/-/commit/b098ec6631a85880f818f2dd25c437d509e53680
FROM registry.opensuse.org/opensuse/leap:15.1

RUN zypper update -y && \
    zypper install -y \
           audit-devel \
           augeas \
           augeas-lenses \
           avahi-devel \
           bash-completion \
           ca-certificates \
           ccache \
           clang \
           cppi \
           cyrus-sasl-devel \
           dbus-1-devel \
           device-mapper-devel \
           diffutils \
           dnsmasq \
           dwarves \
           ebtables \
           fuse-devel \
           gcc \
           gettext \
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
           libudev-devel \
           libwsman-devel \
           libxml2 \
           libxml2-devel \
           libxslt \
           libyajl-devel \
           lvm2 \
           make \
           nfs-utils \
           ninja \
           numad \
           open-iscsi \
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
           qemu-tools \
           radvd \
           readline-devel \
           rpcgen \
           rpm-build \
           sanlock-devel \
           scrub \
           systemtap-sdt-devel \
           wireshark-devel \
           xen-devel \
           xfsprogs-devel && \
    zypper clean --all && \
    rpm -qa | sort > /packages.txt && \
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
