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
    with_dtrace=no
    with_storage_scsi=no
fi


AM_CONDITIONAL([WITH_LINUX], [test "$with_linux" = "yes"])
AM_CONDITIONAL([WITH_FREEBSD], [test "$with_freebsd" = "yes"])
AM_CONDITIONAL([WITH_MACOS], [test "$with_macos" = "yes"])

# Check for compiler and library settings.

LIBVIRT_ARG_NSS
LIBVIRT_ARG_PM_UTILS

LIBVIRT_CHECK_NWFILTER
LIBVIRT_CHECK_PM_UTILS



dnl
dnl Virtualization drivers check
dnl

LIBVIRT_DRIVER_ARG_VZ
LIBVIRT_DRIVER_ARG_NETWORK
LIBVIRT_DRIVER_ARG_INTERFACE

LIBVIRT_DRIVER_CHECK_VZ
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

dnl Python3 < 3.7 treats the C locale as 7-bit only.
dnl We must force env vars so it treats it as UTF-8
dnl regardless of the user's locale.
RUNUTF8="LC_ALL= LANG=C LC_CTYPE=en_US.UTF-8"
AC_SUBST(RUNUTF8)


dnl MinGW checks
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
LIBVIRT_DRIVER_RESULT_VZ
LIBVIRT_DRIVER_RESULT_NETWORK
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
LIBVIRT_RESULT_NSS
LIBVIRT_RESULT_PM_UTILS
LIBVIRT_RESULT_RBD
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Windows])
AC_MSG_NOTICE([])
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
