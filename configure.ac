dnl Process this file with autoconf to produce a configure script.

dnl Copyright (C) 2005-2015 Red Hat, Inc.
dnl
dnl This library is free software; you can redistribute it and/or
dnl modify it under the terms of the GNU Lesser General Public
dnl License as published by the Free Software Foundation; either
dnl version 2.1 of the License, or (at your option) any later version.
dnl
dnl This library is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl Lesser General Public License for more details.
dnl
dnl You should have received a copy of the GNU Lesser General Public
dnl License along with this library.  If not, see
dnl <http://www.gnu.org/licenses/>.

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
dnl Make automake keep quiet about wildcards & other GNUmake-isms
AM_INIT_AUTOMAKE([
    foreign
    -Wno-portability
    tar-pax
    no-dist-gzip
    dist-xz
    subdir-objects
    ])
dnl older automake's default of ARFLAGS=cru is noisy on newer binutils;
dnl we don't really need the 'u' even in older toolchains.  Then there is
dnl older libtool, which spelled it AR_FLAGS
m4_divert_text([DEFAULTS], [: "${ARFLAGS=cr} ${AR_FLAGS=cr}"])

# Default to using the silent-rules feature when possible.  Formatting
# chosen to bypass 'grep' checks that cause older automake to warn.
# Users (include rpm) can still change the default at configure time.
m4_ifndef([AM_SILENT_RULES],
 [m4_define([AM_SILENT_RULES],[])])AM_SILENT_RULES([yes])

AC_CANONICAL_HOST

dnl Where we look for daemons and admin binaries during configure
LIBVIRT_SBIN_PATH="$PATH:/sbin:/usr/sbin:/usr/local/sbin"

dnl Checks for C compiler.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_CPP

dnl get 64-int interfaces on 32-bit platforms
CFLAGS="$CFLAGS -D_FILE_OFFSET_BITS=64"

dnl Support building Win32 DLLs (must appear *before* AM_PROG_LIBTOOL)
AC_LIBTOOL_WIN32_DLL

m4_ifndef([LT_INIT], [
  AM_PROG_LIBTOOL
], [
  LT_INIT([shared disable-static])
])
AM_PROG_CC_C_O
AM_PROG_LD

dnl Specify if we rely on ifconfig instead of iproute2 (e.g. in case
dnl we're working on BSD)
want_ifconfig=no

dnl Make some notes about which OS we're compiling for, as the lxc and qemu
dnl drivers require linux headers, and storage_mpath, dtrace, and nwfilter
dnl are also linux specific.  The "network" and storage_fs drivers are known
dnl to not work on macOS presently, so we also make a note if compiling
dnl for that

with_linux=no with_macos=no with_freebsd=no with_win=no
case $host in
  *-*-linux*) with_linux=yes ;;
  *-*-darwin*) with_macos=yes ;;
  *-*-freebsd*) with_freebsd=yes ;;
  *-*-mingw* | *-*-msvc* ) with_win=yes ;;
esac

if test $with_linux = no; then
    if test "x$with_lxc" != xyes
    then
        with_lxc=no
    fi
    with_dtrace=no
    with_storage_scsi=no
fi

if test $with_freebsd = yes; then
    want_ifconfig=yes
    with_firewalld=no
fi


AM_CONDITIONAL([WITH_LINUX], [test "$with_linux" = "yes"])
AM_CONDITIONAL([WITH_FREEBSD], [test "$with_freebsd" = "yes"])
AM_CONDITIONAL([WITH_MACOS], [test "$with_macos" = "yes"])

if test "$with_win" = "yes" ; then
  # We don't support the daemon yet
  with_libvirtd=no
fi

# The daemon requires remote support.  Likewise, if we are not using
# RPC, we don't need several libraries.
if test "$with_remote" = "no" ; then
  with_libvirtd=no
  with_ssh2=no
  with_sasl=no
  with_libssh=no
fi
# Stateful drivers are useful only when building the daemon.
if test "$with_libvirtd" = "no" ; then
  with_qemu=no
  with_lxc=no
  with_libxl=no
  with_vbox=no
fi

# Check for compiler and library settings.

LIBVIRT_ARG_APPARMOR
LIBVIRT_ARG_ATTR
LIBVIRT_ARG_AUDIT
LIBVIRT_ARG_BASH_COMPLETION
LIBVIRT_ARG_BLKID
LIBVIRT_ARG_CAPNG
LIBVIRT_ARG_CURL
LIBVIRT_ARG_DBUS
LIBVIRT_ARG_FIREWALLD
LIBVIRT_ARG_FIREWALLD_ZONE
LIBVIRT_ARG_FUSE
LIBVIRT_ARG_GLUSTER
LIBVIRT_ARG_HAL
LIBVIRT_ARG_LIBISCSI
LIBVIRT_ARG_LIBPCAP
LIBVIRT_ARG_LIBSSH
LIBVIRT_ARG_LIBXML
LIBVIRT_ARG_MACVTAP
LIBVIRT_ARG_NETCF
LIBVIRT_ARG_NLS
LIBVIRT_ARG_NSS
LIBVIRT_ARG_NUMACTL
LIBVIRT_ARG_OPENWSMAN
LIBVIRT_ARG_PCIACCESS
LIBVIRT_ARG_PM_UTILS
LIBVIRT_ARG_POLKIT
LIBVIRT_ARG_READLINE
LIBVIRT_ARG_SANLOCK
LIBVIRT_ARG_SASL
LIBVIRT_ARG_SELINUX
LIBVIRT_ARG_SSH2
LIBVIRT_ARG_UDEV
LIBVIRT_ARG_VIRTUALPORT
LIBVIRT_ARG_WIRESHARK
LIBVIRT_ARG_YAJL

LIBVIRT_CHECK_ACL
LIBVIRT_CHECK_APPARMOR
LIBVIRT_CHECK_ATTR
LIBVIRT_CHECK_AUDIT
LIBVIRT_CHECK_BASH_COMPLETION
LIBVIRT_CHECK_BLKID
LIBVIRT_CHECK_CAPNG
LIBVIRT_CHECK_CURL
LIBVIRT_CHECK_DBUS
LIBVIRT_CHECK_DEVMAPPER
LIBVIRT_CHECK_DLOPEN
LIBVIRT_CHECK_FIREWALLD
LIBVIRT_CHECK_FIREWALLD_ZONE
LIBVIRT_CHECK_FUSE
LIBVIRT_CHECK_GLIB
LIBVIRT_CHECK_GLUSTER
LIBVIRT_CHECK_GNUTLS
LIBVIRT_CHECK_HAL
LIBVIRT_CHECK_LIBISCSI
LIBVIRT_CHECK_LIBNL
LIBVIRT_CHECK_LIBPARTED
LIBVIRT_CHECK_LIBPCAP
LIBVIRT_CHECK_LIBSSH
LIBVIRT_CHECK_LIBXML
LIBVIRT_CHECK_MACVTAP
LIBVIRT_CHECK_NETCF
LIBVIRT_CHECK_NLS
LIBVIRT_CHECK_NUMACTL
LIBVIRT_CHECK_NWFILTER
LIBVIRT_CHECK_OPENWSMAN
LIBVIRT_CHECK_PCIACCESS
LIBVIRT_CHECK_PM_UTILS
LIBVIRT_CHECK_POLKIT
LIBVIRT_CHECK_PTHREAD
LIBVIRT_CHECK_READLINE
LIBVIRT_CHECK_SANLOCK
LIBVIRT_CHECK_SASL
LIBVIRT_CHECK_SELINUX
LIBVIRT_CHECK_SSH2
LIBVIRT_CHECK_UDEV
LIBVIRT_CHECK_VIRTUALPORT
LIBVIRT_CHECK_WIRESHARK
LIBVIRT_CHECK_XDR
LIBVIRT_CHECK_YAJL

AC_CHECK_SIZEOF([long])


AC_CHECK_LIB([intl],[gettext],[])
AC_CHECK_LIB([util],[openpty],[])


dnl
dnl Check for external programs
dnl

LIBVIRT_CHECK_EXTERNAL_PROGRAMS

dnl
dnl Virtualization drivers check
dnl

LIBVIRT_DRIVER_ARG_QEMU
LIBVIRT_DRIVER_ARG_OPENVZ
LIBVIRT_DRIVER_ARG_VMWARE
LIBVIRT_DRIVER_ARG_LIBXL
LIBVIRT_DRIVER_ARG_VBOX
LIBVIRT_DRIVER_ARG_LXC
LIBVIRT_DRIVER_ARG_VZ
LIBVIRT_DRIVER_ARG_BHYVE
LIBVIRT_DRIVER_ARG_ESX
LIBVIRT_DRIVER_ARG_HYPERV
LIBVIRT_DRIVER_ARG_TEST
LIBVIRT_DRIVER_ARG_REMOTE
LIBVIRT_DRIVER_ARG_LIBVIRTD
LIBVIRT_DRIVER_ARG_NETWORK
LIBVIRT_DRIVER_ARG_INTERFACE

LIBVIRT_DRIVER_CHECK_QEMU
LIBVIRT_DRIVER_CHECK_OPENVZ
LIBVIRT_DRIVER_CHECK_VMWARE
LIBVIRT_DRIVER_CHECK_LIBXL
LIBVIRT_DRIVER_CHECK_VBOX
LIBVIRT_DRIVER_CHECK_LXC
LIBVIRT_DRIVER_CHECK_VZ
LIBVIRT_DRIVER_CHECK_BHYVE
LIBVIRT_DRIVER_CHECK_ESX
LIBVIRT_DRIVER_CHECK_HYPERV
LIBVIRT_DRIVER_CHECK_TEST
LIBVIRT_DRIVER_CHECK_REMOTE
LIBVIRT_DRIVER_CHECK_LIBVIRTD
LIBVIRT_DRIVER_CHECK_NETWORK
LIBVIRT_DRIVER_CHECK_INTERFACE


dnl
dnl in case someone want to build static binaries
dnl STATIC_BINARIES="-static"
dnl
STATIC_BINARIES=
AC_SUBST([STATIC_BINARIES])

dnl
dnl Miscellaneous checks
dnl

LIBVIRT_ARG_DTRACE
LIBVIRT_ARG_NUMAD
LIBVIRT_ARG_INIT_SCRIPT
LIBVIRT_ARG_CHRDEV_LOCK_FILES
LIBVIRT_ARG_LOADER_NVRAM
LIBVIRT_ARG_LOGIN_SHELL
LIBVIRT_ARG_HOST_VALIDATE
LIBVIRT_ARG_TLS_PRIORITY
LIBVIRT_ARG_SYSCTL_CONFIG


LIBVIRT_CHECK_DTRACE
LIBVIRT_CHECK_NUMAD
LIBVIRT_CHECK_INIT_SCRIPT
LIBVIRT_CHECK_CHRDEV_LOCK_FILES
LIBVIRT_CHECK_LOADER_NVRAM
LIBVIRT_CHECK_LOGIN_SHELL
LIBVIRT_CHECK_HOST_VALIDATE
LIBVIRT_CHECK_TLS_PRIORITY
LIBVIRT_CHECK_SYSCTL_CONFIG
LIBVIRT_CHECK_NSS


dnl Need to test if pkg-config exists
PKG_PROG_PKG_CONFIG


dnl Security driver checks
LIBVIRT_SECDRIVER_ARG_SELINUX
LIBVIRT_SECDRIVER_ARG_APPARMOR

LIBVIRT_SECDRIVER_CHECK_SELINUX
LIBVIRT_SECDRIVER_CHECK_APPARMOR


LIBVIRT_ARG_WITH_FEATURE([SECRETS], [local secrets management driver], [yes])

if test "$with_libvirtd" = "no"; then
  with_secrets=no
fi
if test "$with_secrets" = "yes" ; then
  AC_DEFINE_UNQUOTED([WITH_SECRETS], 1, [whether local secrets management driver is available])
fi
AM_CONDITIONAL([WITH_SECRETS], [test "$with_secrets" = "yes"])


dnl
dnl Storage driver checks
dnl

LIBVIRT_STORAGE_ARG_DIR
LIBVIRT_STORAGE_ARG_FS
LIBVIRT_STORAGE_ARG_LVM
LIBVIRT_STORAGE_ARG_ISCSI
LIBVIRT_STORAGE_ARG_ISCSI_DIRECT
LIBVIRT_STORAGE_ARG_SCSI
LIBVIRT_STORAGE_ARG_MPATH
LIBVIRT_STORAGE_ARG_DISK
LIBVIRT_STORAGE_ARG_RBD
LIBVIRT_STORAGE_ARG_SHEEPDOG
LIBVIRT_STORAGE_ARG_GLUSTER
LIBVIRT_STORAGE_ARG_ZFS
LIBVIRT_STORAGE_ARG_VSTORAGE

if test "$with_libvirtd" = "no"; then
  with_storage_dir=no
  with_storage_fs=no
  with_storage_lvm=no
  with_storage_iscsi=no
  with_storage_iscsi_direct=no
  with_storage_scsi=no
  with_storage_mpath=no
  with_storage_disk=no
  with_storage_rbd=no
  with_storage_sheepdog=no
  with_storage_gluster=no
  with_storage_zfs=no
  with_storage_vstorage=no
fi

dnl storage-fs does not work on macOS

if test "$with_macos" = "yes"; then
  with_storage_fs=no
fi

LIBVIRT_STORAGE_CHECK_DIR
LIBVIRT_STORAGE_CHECK_FS
LIBVIRT_STORAGE_CHECK_LVM
LIBVIRT_STORAGE_CHECK_ISCSI
LIBVIRT_STORAGE_CHECK_ISCSI_DIRECT
LIBVIRT_STORAGE_CHECK_SCSI
LIBVIRT_STORAGE_CHECK_MPATH
LIBVIRT_STORAGE_CHECK_DISK
LIBVIRT_STORAGE_CHECK_RBD
LIBVIRT_STORAGE_CHECK_SHEEPDOG
LIBVIRT_STORAGE_CHECK_GLUSTER
LIBVIRT_STORAGE_CHECK_ZFS
LIBVIRT_STORAGE_CHECK_VSTORAGE

with_storage=no
for backend in dir fs lvm iscsi iscsi_direct scsi mpath rbd disk; do
    if eval test \$with_storage_$backend = yes; then
        with_storage=yes
        break
    fi
done
if test $with_storage = yes; then
    AC_DEFINE([WITH_STORAGE], [1],
      [Define to 1 if at least one storage backend is in use])
fi
AM_CONDITIONAL([WITH_STORAGE], [test "$with_storage" = "yes"])

dnl Allow perl/python overrides
AC_PATH_PROGS([PYTHON], [python3])
if test -z "$PYTHON"; then
    AC_MSG_ERROR(['python3' binary is required to build libvirt])
fi
AC_DEFINE_UNQUOTED([PYTHON], "$PYTHON", [path to python binary])
AC_PATH_PROG([FLAKE8], [flake8])
if test -z "$FLAKE8"; then
    AC_MSG_WARN(['flake8' binary is required to check python code style])
fi

dnl Python3 < 3.7 treats the C locale as 7-bit only.
dnl We must force env vars so it treats it as UTF-8
dnl regardless of the user's locale.
RUNUTF8="LC_ALL= LANG=C LC_CTYPE=en_US.UTF-8"
AC_SUBST(RUNUTF8)


AC_PATH_PROG([PERL], [perl])
if test -z "$PERL"; then
         AC_MSG_ERROR(['perl' binary is required to build libvirt])
fi

dnl MinGW checks
LIBVIRT_WIN_CHECK_COMMON
LIBVIRT_WIN_CHECK_MINGW
LIBVIRT_WIN_CHECK_SYMBOLS
LIBVIRT_WIN_CHECK_WINDRES


dnl Driver-Modules library support
LIBVIRT_CHECK_DRIVER_MODULES


# Set LV_LIBTOOL_OBJDIR to "." or $lt_cv_objdir, depending on whether
# we're building shared libraries.  This is the name of the directory
# in which .o files will be created.
test "$enable_shared" = no && lt_cv_objdir=.
LV_LIBTOOL_OBJDIR=${lt_cv_objdir-.}
AC_SUBST([LV_LIBTOOL_OBJDIR])


with_nodedev=no;
if test "$with_hal" = "yes" || test "$with_udev" = "yes";
then
  with_nodedev=yes
  AC_DEFINE_UNQUOTED([WITH_NODE_DEVICES], 1, [with node device driver])
fi
AM_CONDITIONAL([WITH_NODE_DEVICES], [test "$with_nodedev" = "yes"])


# Check for BSD kvm (kernel memory interface)
if test $with_freebsd = yes; then
     AC_CHECK_LIB([kvm], [kvm_getprocs], [],
                  [AC_MSG_ERROR([BSD kernel memory interface library is required to build on FreeBSD])]
                 )
fi

# Check if we need to look for ifconfig
if test "$want_ifconfig" = "yes"; then
     AC_PATH_PROG([IFCONFIG_PATH], [ifconfig])
     if test -z "$IFCONFIG_PATH"; then
         AC_MSG_ERROR([Failed to find ifconfig.])
     fi
     AC_DEFINE_UNQUOTED([IFCONFIG_PATH], "$IFCONFIG_PATH", [path to ifconfig binary])
fi

GNUmakefile=GNUmakefile
m4_if(m4_version_compare([2.61a.100],
        m4_defn([m4_PACKAGE_VERSION])), [1], [],
      [AC_CONFIG_LINKS([$GNUmakefile:$GNUmakefile], [],
        [GNUmakefile=$GNUmakefile])])

AC_CONFIG_FILES([run],
                [chmod +x,-w run])
AC_CONFIG_FILES([\
        Makefile src/Makefile docs/Makefile \
        .color_coded \
        .ycm_extra_conf.py \
        libvirt.pc \
        libvirt-qemu.pc \
        libvirt-lxc.pc \
        libvirt-admin.pc \
        src/libvirt.pc \
        src/libvirt-qemu.pc \
        src/libvirt-lxc.pc \
        libvirt.spec mingw-libvirt.spec \
        po/Makefile \
        examples/Makefile \
        tests/Makefile \
        tools/Makefile])
AC_OUTPUT

AC_MSG_NOTICE([])
AC_MSG_NOTICE([Configuration summary])
AC_MSG_NOTICE([=====================])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Drivers])
AC_MSG_NOTICE([])
LIBVIRT_DRIVER_RESULT_QEMU
LIBVIRT_DRIVER_RESULT_OPENVZ
LIBVIRT_DRIVER_RESULT_VMWARE
LIBVIRT_DRIVER_RESULT_VBOX
LIBVIRT_DRIVER_RESULT_LIBXL
LIBVIRT_DRIVER_RESULT_LXC
LIBVIRT_DRIVER_RESULT_ESX
LIBVIRT_DRIVER_RESULT_HYPERV
LIBVIRT_DRIVER_RESULT_VZ
LIBVIRT_DRIVER_RESULT_BHYVE
LIBVIRT_DRIVER_RESULT_TEST
LIBVIRT_DRIVER_RESULT_REMOTE
LIBVIRT_DRIVER_RESULT_NETWORK
LIBVIRT_DRIVER_RESULT_LIBVIRTD
LIBVIRT_DRIVER_RESULT_INTERFACE
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Storage Drivers])
AC_MSG_NOTICE([])
LIBVIRT_STORAGE_RESULT_DIR
LIBVIRT_STORAGE_RESULT_FS
LIBVIRT_STORAGE_RESULT_LVM
LIBVIRT_STORAGE_RESULT_ISCSI
LIBVIRT_STORAGE_RESULT_ISCSI_DIRECT
LIBVIRT_STORAGE_RESULT_SCSI
LIBVIRT_STORAGE_RESULT_MPATH
LIBVIRT_STORAGE_RESULT_DISK
LIBVIRT_STORAGE_RESULT_RBD
LIBVIRT_STORAGE_RESULT_SHEEPDOG
LIBVIRT_STORAGE_RESULT_GLUSTER
LIBVIRT_STORAGE_RESULT_ZFS
LIBVIRT_STORAGE_RESULT_VSTORAGE
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Security Drivers])
AC_MSG_NOTICE([])
LIBVIRT_SECDRIVER_RESULT_SELINUX
LIBVIRT_SECDRIVER_RESULT_APPARMOR
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Driver Loadable Modules])
AC_MSG_NOTICE([])
LIBVIRT_RESULT_DRIVER_MODULES
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Libraries])
AC_MSG_NOTICE([])
LIBVIRT_RESULT_ACL
LIBVIRT_RESULT_APPARMOR
LIBVIRT_RESULT_ATTR
LIBVIRT_RESULT_AUDIT
LIBVIRT_RESULT_BASH_COMPLETION
LIBVIRT_RESULT_BLKID
LIBVIRT_RESULT_CAPNG
LIBVIRT_RESULT_CURL
LIBVIRT_RESULT_DBUS
LIBVIRT_RESULT_DLOPEN
LIBVIRT_RESULT_FIREWALLD
LIBVIRT_RESULT_FIREWALLD_ZONE
LIBVIRT_RESULT_FUSE
LIBVIRT_RESULT_GLIB
LIBVIRT_RESULT_GLUSTER
LIBVIRT_RESULT_GNUTLS
LIBVIRT_RESULT_HAL
LIBVIRT_RESULT_LIBISCSI
LIBVIRT_RESULT_LIBNL
LIBVIRT_RESULT_LIBPCAP
LIBVIRT_RESULT_LIBSSH
LIBVIRT_RESULT_LIBXL
LIBVIRT_RESULT_LIBXML
LIBVIRT_RESULT_MACVTAP
LIBVIRT_RESULT_NETCF
LIBVIRT_RESULT_NLS
LIBVIRT_RESULT_NSS
LIBVIRT_RESULT_NUMACTL
LIBVIRT_RESULT_OPENWSMAN
LIBVIRT_RESULT_PCIACCESS
LIBVIRT_RESULT_PM_UTILS
LIBVIRT_RESULT_POLKIT
LIBVIRT_RESULT_RBD
LIBVIRT_RESULT_READLINE
LIBVIRT_RESULT_SANLOCK
LIBVIRT_RESULT_SASL
LIBVIRT_RESULT_SELINUX
LIBVIRT_RESULT_SSH2
LIBVIRT_RESULT_UDEV
LIBVIRT_RESULT_VIRTUALPORT
LIBVIRT_RESULT_XDR
LIBVIRT_RESULT_YAJL
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Windows])
AC_MSG_NOTICE([])
LIBVIRT_WIN_RESULT_COMMON
LIBVIRT_WIN_RESULT_WINDRES
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Miscellaneous])
AC_MSG_NOTICE([])
LIBVIRT_RESULT_DTRACE
LIBVIRT_RESULT_NUMAD
LIBVIRT_RESULT_INIT_SCRIPT
LIBVIRT_RESULT_CHRDEV_LOCK_FILES
LIBVIRT_RESULT_LOADER_NVRAM
LIBVIRT_RESULT_LOGIN_SHELL
LIBVIRT_RESULT_HOST_VALIDATE
LIBVIRT_RESULT_TLS_PRIORITY
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Developer Tools])
AC_MSG_NOTICE([])
LIBVIRT_RESULT_WIRESHARK
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Privileges])
AC_MSG_NOTICE([])
LIBVIRT_RESULT_QEMU_PRIVILEGES
AC_MSG_NOTICE([])
