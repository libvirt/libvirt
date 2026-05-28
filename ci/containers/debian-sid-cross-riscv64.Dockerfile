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
                      black \
                      ca-certificates \
                      ccache \
                      codespell \
                      cpp \
                      diffutils \
                      dwarves \
                      ebtables \
                      flake8 \
                      gettext \
                      git \
                      grep \
                      libclang-rt-dev \
                      libnbd-dev \
                      libxml2-utils \
                      locales \
                      make \
                      meson \
                      ninja-build \
                      perl-base \
                      pkgconf \
                      python3 \
                      python3-docutils \
                      python3-pytest \
                      qemu-utils \
                      sed \
                      xsltproc && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y && \
    sed -Ei 's,^# (en_US\.UTF-8 .*)$,\1,' /etc/locale.gen && \
    dpkg-reconfigure locales && \
    rm -f /usr/lib*/python3*/EXTERNALLY-MANAGED

ENV CCACHE_WRAPPERSDIR="/usr/libexec/ccache-wrappers"
ENV LANG="en_US.UTF-8"
ENV MAKE="/usr/bin/make"
ENV NINJA="/usr/bin/ninja"
ENV PYTHON="/usr/bin/python3"

RUN export DEBIAN_FRONTEND=noninteractive && \
    dpkg --add-architecture riscv64 && \
    eatmydata apt-get update && \
    eatmydata apt-get dist-upgrade -y && \
    eatmydata apt-get install --no-install-recommends -y dpkg-dev && \
    eatmydata apt-get install --no-install-recommends -y \
                      gcc-riscv64-linux-gnu \
                      libacl1-dev:riscv64 \
                      libapparmor-dev:riscv64 \
                      libattr1-dev:riscv64 \
                      libaudit-dev:riscv64 \
                      libblkid-dev:riscv64 \
                      libc6-dev:riscv64 \
                      libcap-ng-dev:riscv64 \
                      libcurl4-gnutls-dev:riscv64 \
                      libdevmapper-dev:riscv64 \
                      libfuse3-dev:riscv64 \
                      libglib2.0-dev:riscv64 \
                      libglusterfs-dev:riscv64 \
                      libgnutls28-dev:riscv64 \
                      libiscsi-dev:riscv64 \
                      libjson-c-dev:riscv64 \
                      libnl-3-dev:riscv64 \
                      libnl-route-3-dev:riscv64 \
                      libnuma-dev:riscv64 \
                      libparted-dev:riscv64 \
                      libpcap0.8-dev:riscv64 \
                      libpciaccess-dev:riscv64 \
                      librbd-dev:riscv64 \
                      libreadline-dev:riscv64 \
                      libsanlock-dev:riscv64 \
                      libsasl2-dev:riscv64 \
                      libselinux1-dev:riscv64 \
                      libssh-dev:riscv64 \
                      libssh2-1-dev:riscv64 \
                      libtirpc-dev:riscv64 \
                      libudev-dev:riscv64 \
                      libxml2-dev:riscv64 \
                      systemtap-sdt-dev:riscv64 && \
    eatmydata apt-get autoremove -y && \
    eatmydata apt-get autoclean -y && \
    mkdir -p /usr/local/share/meson/cross && \
    printf "[binaries]\n\
c = '/usr/bin/riscv64-linux-gnu-gcc'\n\
ar = '/usr/bin/riscv64-linux-gnu-gcc-ar'\n\
strip = '/usr/bin/riscv64-linux-gnu-strip'\n\
pkgconfig = '/usr/bin/riscv64-linux-gnu-pkg-config'\n\
\n\
[host_machine]\n\
system = 'linux'\n\
cpu_family = 'riscv64'\n\
cpu = 'riscv64'\n\
endian = 'little'\n" > /usr/local/share/meson/cross/riscv64-linux-gnu && \
    dpkg-query --showformat '${Package}_${Version}_${Architecture}\n' --show > /packages.txt && \
    mkdir -p /usr/libexec/ccache-wrappers && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/riscv64-linux-gnu-cc && \
    ln -s /usr/bin/ccache /usr/libexec/ccache-wrappers/riscv64-linux-gnu-gcc

ENV ABI="riscv64-linux-gnu"
ENV MESON_OPTS="--cross-file=riscv64-linux-gnu"
