# THIS FILE WAS AUTO-GENERATED
#
#  $ lcitool manifest ci/manifest.yml
#
# https://gitlab.com/libvirt/libvirt-ci

FROM registry.opensuse.org/opensuse/tumbleweed:latest

RUN zypper update -y && \
    zypper install -y \
           audit-devel \
           augeas \
           augeas-lenses \
           bash-completion \
           ca-certificates \
           ccache \
           clang \
           cpp \
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
           gettext-runtime \
           git \
           glib2-devel \
           glibc-devel \
           glibc-locale \
           glusterfs-devel \
           grep \
           iproute2 \
           iptables \
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
           meson \
           nfs-utils \
           ninja \
           numad \
           open-iscsi \
           parted \
           parted-devel \
           perl-base \
           pkgconfig \
           polkit \
           python3-base \
           python3-docutils \
           python3-flake8 \
           qemu-tools \
           radvd \
           readline-devel \
           rpcgen \
           rpm-build \
           sanlock-devel \
           scrub \
           sed \
           systemtap-sdt-devel \
           wireshark-devel \
           xen-devel \
           xfsprogs-devel && \
    zypper clean --all && \
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
