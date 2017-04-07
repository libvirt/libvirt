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

AC_INIT([libvirt], [3.3.0], [libvir-list@redhat.com], [], [http://libvirt.org])
AC_CONFIG_SRCDIR([src/libvirt.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AH_BOTTOM([#include <config-post.h>])
AC_CONFIG_MACRO_DIR([m4])
dnl Make automake keep quiet about wildcards & other GNUmake-isms; also keep
dnl quiet about the fact that we intentionally cater to automake 1.9
AM_INIT_AUTOMAKE([-Wno-portability -Wno-obsolete tar-pax no-dist-gzip dist-xz subdir-objects])
dnl older automake's default of ARFLAGS=cru is noisy on newer binutils;
dnl we don't really need the 'u' even in older toolchains.  Then there is
dnl older libtool, which spelled it AR_FLAGS
m4_divert_text([DEFAULTS], [: "${ARFLAGS=cr} ${AR_FLAGS=cr}"])

# Maintainer note - comment this line out if you plan to rerun
# GNULIB_POSIXCHECK testing to see if libvirt should be using more modules.
# Leave it uncommented for normal releases, for faster ./configure.
gl_ASSERT_NO_GNULIB_POSIXCHECK

# Default to using the silent-rules feature when possible.  Formatting
# chosen to bypass 'grep' checks that cause older automake to warn.
# Users (include rpm) can still change the default at configure time.
m4_ifndef([AM_SILENT_RULES],
 [m4_define([AM_SILENT_RULES],[])])AM_SILENT_RULES([yes])

AC_CANONICAL_HOST

# First extract pieces from the version number string
LIBVIRT_MAJOR_VERSION=`echo $VERSION | awk -F. '{print $1}'`
LIBVIRT_MINOR_VERSION=`echo $VERSION | awk -F. '{print $2}'`
LIBVIRT_MICRO_VERSION=`echo $VERSION | awk -F. '{print $3}'`
LIBVIRT_VERSION=$LIBVIRT_MAJOR_VERSION.$LIBVIRT_MINOR_VERSION.$LIBVIRT_MICRO_VERSION$LIBVIRT_MICRO_VERSION_SUFFIX
LIBVIRT_VERSION_NUMBER=`expr $LIBVIRT_MAJOR_VERSION \* 1000000 + $LIBVIRT_MINOR_VERSION \* 1000 + $LIBVIRT_MICRO_VERSION`

# In libtool terminology we need to figure out:
#
# CURRENT
#     The most recent interface number that this library implements.
#
# REVISION
#     The implementation number of the CURRENT interface.
#
# AGE
#     The difference between the newest and oldest interfaces that this
#     library implements.
#
# In other words, the library implements all the interface numbers
# in the range from number `CURRENT - AGE' to `CURRENT'.
#
# Libtool assigns the soname version from `CURRENT - AGE', and we
# don't want that to ever change in libvirt. ie it must always be
# zero, to produce libvirt.so.0.
#
# We would, however, like the libvirt version number reflected
# in the so version'd symlinks, and this is based on AGE.REVISION
# eg  libvirt.so.0.AGE.REVISION
#
# Assuming we do ever want to break soname version, this can
# toggled. But seriously, don't ever touch this.
LIBVIRT_SONUM=0

# The following examples show what libtool will do
#
# Input: 0.9.14 ->   libvirt.so.0.9.14
# Input: 1.0.0  ->   libvirt.so.0.1000.0
# Input: 2.5.8  ->   libvirt.so.0.2005.8
#
AGE=`expr $LIBVIRT_MAJOR_VERSION '*' 1000 + $LIBVIRT_MINOR_VERSION`
REVISION=$LIBVIRT_MICRO_VERSION
CURRENT=`expr $LIBVIRT_SONUM + $AGE`
LIBVIRT_VERSION_INFO=$CURRENT:$REVISION:$AGE

AC_SUBST([LIBVIRT_MAJOR_VERSION])
AC_SUBST([LIBVIRT_MINOR_VERSION])
AC_SUBST([LIBVIRT_MICRO_VERSION])
AC_SUBST([LIBVIRT_SONUM])
AC_SUBST([LIBVIRT_VERSION])
AC_SUBST([LIBVIRT_VERSION_INFO])
AC_SUBST([LIBVIRT_VERSION_NUMBER])

LIBVIRT_ARG_WITH([PACKAGER], [Extra packager name], [no])
LIBVIRT_ARG_WITH([PACKAGER_VERSION], [Extra packager version], [no])
if test "x$with_packager" != "xno"
then
  AC_DEFINE_UNQUOTED([PACKAGER], ["$with_packager"],
                     [Extra package name])
fi
if test "x$with_packager_version" != "xno"
then
  AC_DEFINE_UNQUOTED([PACKAGER_VERSION], ["$with_packager_version"],
                     [Extra package version])
fi

dnl Where we look for daemons and admin binaries during configure
LIBVIRT_SBIN_PATH="$PATH:/sbin:/usr/sbin:/usr/local/sbin"

dnl Checks for C compiler.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_CPP

dnl Setting AB_VERSION makes the 'autobuild' lines of configure output
dnl slightly more useful
if test -d $srcdir/.git && git --version >/dev/null 2>&1 ; then
  AB_VERSION=`cd $srcdir && git describe --match 'v[[0-9]]*' 2>/dev/null`
fi

gl_EARLY
gl_INIT

AC_TYPE_UID_T

dnl Support building Win32 DLLs (must appear *before* AM_PROG_LIBTOOL)
AC_LIBTOOL_WIN32_DLL

AC_HEADER_MAJOR

m4_ifndef([LT_INIT], [
  AM_PROG_LIBTOOL
], [
  LT_INIT([shared disable-static])
])
AM_PROG_CC_C_O
AM_PROG_LD

AC_MSG_CHECKING([for how to mark DSO non-deletable at runtime])
LIBVIRT_NODELETE=
`$LD --help 2>&1 | grep -- "-z nodelete" >/dev/null` && \
    LIBVIRT_NODELETE="-Wl,-z -Wl,nodelete"
AC_MSG_RESULT([$LIBVIRT_NODELETE])
AC_SUBST([LIBVIRT_NODELETE])

AC_MSG_CHECKING([for how to set DSO symbol versions])
case "$host" in
  *-*-mingw* | *-*-msvc* )
    # mingw's ld has the --version-script parameter, but it requires a .def file
    # instead to work properly, therefore clear --version-script here and use
    # -Wl, to pass the .def file to the linker
    # cygwin's ld has the --version-script parameter too, but for some reason
    # it's working there as expected
    VERSION_SCRIPT_FLAGS="-Wl,"
    ;;
  * )
    VERSION_SCRIPT_FLAGS=-Wl,--version-script=
      `$LD --help 2>&1 | grep -- --version-script >/dev/null` || \
        VERSION_SCRIPT_FLAGS="-Wl,-M -Wl,"
    ;;
esac
AC_MSG_RESULT([$VERSION_SCRIPT_FLAGS])
AC_SUBST([VERSION_SCRIPT_FLAGS])

dnl Specify if we rely on ifconfig instead of iproute2 (e.g. in case
dnl we're working on BSD)
want_ifconfig=no

dnl Make some notes about which OS we're compiling for, as the lxc and qemu
dnl drivers require linux headers, and storage_mpath, dtrace, and nwfilter
dnl are also linux specific.  The "network" and storage_fs drivers are known
dnl to not work on MacOS X presently, so we also make a note if compiling
dnl for that

with_linux=no with_osx=no with_freebsd=no with_win=no with_cygwin=no
case $host in
  *-*-linux*) with_linux=yes ;;
  *-*-darwin*) with_osx=yes ;;
  *-*-freebsd*) with_freebsd=yes ;;
  *-*-mingw* | *-*-msvc* ) with_win=yes ;;
  *-*-cygwin*) with_cygwin=yes ;;
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

if test $with_cygwin = yes; then
    with_vbox=no
fi

AM_CONDITIONAL([WITH_LINUX], [test "$with_linux" = "yes"])
AM_CONDITIONAL([WITH_FREEBSD], [test "$with_freebsd" = "yes"])

# We don't support the daemon yet
if test "$with_win" = "yes" ; then
  with_libvirtd=no
fi

# The daemon requires remote support.  Likewise, if we are not using
# RPC, we don't need several libraries.
if test "$with_remote" = "no" ; then
  with_libvirtd=no
  with_gnutls=no
  with_ssh2=no
  with_sasl=no
  with_libssh=no
fi
# Stateful drivers are useful only when building the daemon.
if test "$with_libvirtd" = "no" ; then
  with_qemu=no
  with_xen=no
  with_lxc=no
  with_libxl=no
  with_uml=no
  with_vbox=no
fi

# Check for compiler and library settings.

LIBVIRT_COMPILE_WARNINGS
LIBVIRT_COMPILE_PIE
LIBVIRT_LINKER_RELRO
LIBVIRT_LINKER_NO_INDIRECT

LIBVIRT_ARG_APPARMOR
LIBVIRT_ARG_ATTR
LIBVIRT_ARG_AUDIT
LIBVIRT_ARG_AVAHI
LIBVIRT_ARG_BLKID
LIBVIRT_ARG_CAPNG
LIBVIRT_ARG_CURL
LIBVIRT_ARG_DBUS
LIBVIRT_ARG_FIREWALLD
LIBVIRT_ARG_FUSE
LIBVIRT_ARG_GLUSTER
LIBVIRT_ARG_GNUTLS
LIBVIRT_ARG_HAL
LIBVIRT_ARG_LIBPCAP
LIBVIRT_ARG_LIBSSH
LIBVIRT_ARG_LIBXML
LIBVIRT_ARG_MACVTAP
LIBVIRT_ARG_NETCF
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
LIBVIRT_CHECK_ATOMIC
LIBVIRT_CHECK_ATTR
LIBVIRT_CHECK_AUDIT
LIBVIRT_CHECK_AVAHI
LIBVIRT_CHECK_BLKID
LIBVIRT_CHECK_CAPNG
LIBVIRT_CHECK_CURL
LIBVIRT_CHECK_DBUS
LIBVIRT_CHECK_DEVMAPPER
LIBVIRT_CHECK_DLOPEN
LIBVIRT_CHECK_FIREWALLD
LIBVIRT_CHECK_FUSE
LIBVIRT_CHECK_GLUSTER
LIBVIRT_CHECK_GNUTLS
LIBVIRT_CHECK_HAL
LIBVIRT_CHECK_LIBNL
LIBVIRT_CHECK_LIBPARTED
LIBVIRT_CHECK_LIBPCAP
LIBVIRT_CHECK_LIBSSH
LIBVIRT_CHECK_LIBXML
LIBVIRT_CHECK_MACVTAP
LIBVIRT_CHECK_NETCF
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

dnl Availability of various common functions (non-fatal if missing),
dnl and various less common threadsafe functions
AC_CHECK_FUNCS_ONCE([cfmakeraw fallocate geteuid getgid getgrnam_r \
  getmntent_r getpwuid_r getrlimit getuid if_indextoname kill mmap \
  newlocale posix_fallocate posix_memalign prlimit regexec \
  sched_getaffinity setgroups setns setrlimit symlink sysctlbyname \
  getifaddrs sched_setscheduler unshare])

dnl Availability of various common headers (non-fatal if missing).
AC_CHECK_HEADERS([pwd.h regex.h sys/un.h \
  sys/poll.h syslog.h mntent.h net/ethernet.h linux/magic.h \
  sys/un.h sys/syscall.h sys/sysctl.h netinet/tcp.h ifaddrs.h \
  libtasn1.h sys/ucred.h sys/mount.h])
dnl Check whether endian provides handy macros.
AC_CHECK_DECLS([htole64], [], [], [[#include <endian.h>]])
AC_CHECK_FUNCS([stat stat64 __xstat __xstat64 lstat lstat64 __lxstat __lxstat64])

AC_CHECK_TYPE([struct ifreq],
  [AC_DEFINE([HAVE_STRUCT_IFREQ],[1],
    [Defined if struct ifreq exists in net/if.h])],
  [], [[#include <sys/socket.h>
        #include <net/if.h>
  ]])

AC_CHECK_TYPE([struct sockpeercred],
  [AC_DEFINE([HAVE_STRUCT_SOCKPEERCRED], [1],
    [Defined if struct sockpeercred is available])],
  [], [[#include <sys/socket.h>
  ]])

AC_CHECK_DECLS([ETH_FLAG_TXVLAN, ETH_FLAG_NTUPLE, ETH_FLAG_RXHASH, ETH_FLAG_LRO,
                ETHTOOL_GGSO, ETHTOOL_GGRO, ETHTOOL_GFLAGS, ETHTOOL_GFEATURES,
                ETHTOOL_SCOALESCE, ETHTOOL_GCOALESCE],
  [], [], [[#include <linux/ethtool.h>
  ]])

dnl Our only use of libtasn1.h is in the testsuite, and can be skipped
dnl if the header is not present.  Assume -ltasn1 is present if the
dnl header could be found.
AM_CONDITIONAL([HAVE_LIBTASN1], [test "x$ac_cv_header_libtasn1_h" = "xyes"])

AC_CHECK_LIB([intl],[gettext],[])


dnl
dnl Check for external programs
dnl

LIBVIRT_CHECK_EXTERNAL_PROGRAMS


dnl Specific dir for HTML output ?
LIBVIRT_ARG_WITH([HTML_DIR], [path to base html directory],
                 ['$(datadir)/doc'])
LIBVIRT_ARG_WITH([HTML_SUBDIR], [directory used under html-dir],
                 ['$(PACKAGE)-$(VERSION)/html'])
if test "x$with_html_subdir" != "x" ; then
  HTML_DIR="$with_html_dir/$with_html_subdir"
else
  HTML_DIR="$with_html_dir"
fi
AC_SUBST([HTML_DIR])

dnl if --prefix is /usr, don't use /usr/var for localstatedir
dnl or /usr/etc for sysconfdir
dnl as this makes a lot of things break in testing situations

if test "$prefix" = "/usr" && test "$localstatedir" = '${prefix}/var' ; then
    localstatedir='/var'
fi
if test "$prefix" = "/usr" && test "$sysconfdir" = '${prefix}/etc' ; then
    sysconfdir='/etc'
fi

dnl
dnl Virtualization drivers check
dnl

LIBVIRT_DRIVER_ARG_XEN
LIBVIRT_DRIVER_ARG_QEMU
LIBVIRT_DRIVER_ARG_OPENVZ
LIBVIRT_DRIVER_ARG_VMWARE
LIBVIRT_DRIVER_ARG_PHYP
LIBVIRT_DRIVER_ARG_XENAPI
LIBVIRT_DRIVER_ARG_LIBXL
LIBVIRT_DRIVER_ARG_VBOX
LIBVIRT_DRIVER_ARG_LXC
LIBVIRT_DRIVER_ARG_VZ
LIBVIRT_DRIVER_ARG_BHYVE
LIBVIRT_DRIVER_ARG_UML
LIBVIRT_DRIVER_ARG_ESX
LIBVIRT_DRIVER_ARG_HYPERV
LIBVIRT_DRIVER_ARG_TEST
LIBVIRT_DRIVER_ARG_REMOTE
LIBVIRT_DRIVER_ARG_LIBVIRTD
LIBVIRT_DRIVER_ARG_NETWORK
LIBVIRT_DRIVER_ARG_INTERFACE

LIBVIRT_DRIVER_CHECK_XEN
LIBVIRT_DRIVER_CHECK_QEMU
LIBVIRT_DRIVER_CHECK_OPENVZ
LIBVIRT_DRIVER_CHECK_VMWARE
LIBVIRT_DRIVER_CHECK_PHYP
LIBVIRT_DRIVER_CHECK_XENAPI
LIBVIRT_DRIVER_CHECK_LIBXL
LIBVIRT_DRIVER_CHECK_VBOX
LIBVIRT_DRIVER_CHECK_LXC
LIBVIRT_DRIVER_CHECK_VZ
LIBVIRT_DRIVER_CHECK_BHYVE
LIBVIRT_DRIVER_CHECK_UML
LIBVIRT_DRIVER_CHECK_ESX
LIBVIRT_DRIVER_CHECK_HYPERV
LIBVIRT_DRIVER_CHECK_TEST
LIBVIRT_DRIVER_CHECK_REMOTE
LIBVIRT_DRIVER_CHECK_LIBVIRTD
LIBVIRT_DRIVER_CHECK_NETWORK
LIBVIRT_DRIVER_CHECK_INTERFACE

AM_CONDITIONAL([WITH_XENCONFIG], [test "$with_libxl" = "yes" || test "$with_xen" = "yes"])


dnl
dnl in case someone want to build static binaries
dnl STATIC_BINARIES="-static"
dnl
STATIC_BINARIES=
AC_SUBST([STATIC_BINARIES])

dnl
dnl Miscellaneous checks
dnl

LIBVIRT_ARG_DEBUG
LIBVIRT_ARG_DTRACE
LIBVIRT_ARG_NUMAD
LIBVIRT_ARG_XML_CATALOG
LIBVIRT_ARG_INIT_SCRIPT
LIBVIRT_ARG_CHRDEV_LOCK_FILES
LIBVIRT_ARG_DEFAULT_EDITOR
LIBVIRT_ARG_LOADER_NVRAM
LIBVIRT_ARG_LOGIN_SHELL
LIBVIRT_ARG_HOST_VALIDATE
LIBVIRT_ARG_TLS_PRIORITY
LIBVIRT_ARG_SYSCTL_CONFIG


LIBVIRT_CHECK_DEBUG
LIBVIRT_CHECK_DTRACE
LIBVIRT_CHECK_NUMAD
LIBVIRT_CHECK_XML_CATALOG
LIBVIRT_CHECK_INIT_SCRIPT
LIBVIRT_CHECK_CHRDEV_LOCK_FILES
LIBVIRT_CHECK_DEFAULT_EDITOR
LIBVIRT_CHECK_LOADER_NVRAM
LIBVIRT_CHECK_LOGIN_SHELL
LIBVIRT_CHECK_HOST_VALIDATE
LIBVIRT_CHECK_TLS_PRIORITY
LIBVIRT_CHECK_SYSCTL_CONFIG
LIBVIRT_CHECK_NSS




dnl
dnl check for kvm headers
dnl
AC_CHECK_HEADERS([linux/kvm.h])


AM_CONDITIONAL([WITH_SETUID_RPC_CLIENT], [test "$with_lxc$with_login_shell" != "nono"])


dnl
dnl check for kernel headers required by src/bridge.c
dnl
if test "$with_linux" = "yes"; then
    # Various kernel versions have headers that are not self-standing, but
    # yet are incompatible with the corresponding glibc headers.  In order
    # to guarantee compilation across a wide range of versions (from RHEL 5
    # to rawhide), we first have to probe whether glibc and kernel can be
    # used in tandem; and if not, provide workarounds that ensure that
    # ABI-compatible IPv6 types are present for use by the kernel headers.
    # These probes mirror the usage in virnetdevbridge.c
    AC_CACHE_CHECK(
      [whether <linux/*.h> and <netinet/*.h> headers are compatible],
      [lv_cv_netinet_linux_compatible],
      [AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
        #include <netinet/in.h>
        #include <linux/in6.h>
      ]])],
      [lv_cv_netinet_linux_compatible=yes],
      [lv_cv_netinet_linux_compatible=no])])
    if test "x$lv_cv_netinet_linux_compatible" != xyes; then
      AC_DEFINE([NETINET_LINUX_WORKAROUND], [1],
        [define to 1 if Linux kernel headers require a workaround to avoid
        compilation errors when mixed with glibc netinet headers])
    fi
    AC_CHECK_HEADERS([linux/param.h linux/sockios.h linux/if_bridge.h linux/if_tun.h],,
      [AC_MSG_ERROR([You must install kernel-headers in order to compile libvirt with QEMU or LXC support])],
      [[#include <netinet/in.h>
        #if NETINET_LINUX_WORKAROUND
        # define in6_addr in6_addr_
        # define sockaddr_in6 sockaddr_in6_
        # define ipv6_mreq ipv6_mreq_
        # define in6addr_any in6addr_any_
        # define in6addr_loopback in6addr_loopback_
        #endif
        #include <linux/in6.h>
      ]])
fi


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
  with_storage_scsi=no
  with_storage_mpath=no
  with_storage_disk=no
  with_storage_rbd=no
  with_storage_sheepdog=no
  with_storage_gluster=no
  with_storage_zfs=no
  with_storage_vstorage=no
fi

dnl storage-fs does not work on MacOS X

if test "$with_osx" = "yes"; then
  with_storage_fs=no
fi

LIBVIRT_STORAGE_CHECK_DIR
LIBVIRT_STORAGE_CHECK_FS
LIBVIRT_STORAGE_CHECK_LVM
LIBVIRT_STORAGE_CHECK_ISCSI
LIBVIRT_STORAGE_CHECK_SCSI
LIBVIRT_STORAGE_CHECK_MPATH
LIBVIRT_STORAGE_CHECK_DISK
LIBVIRT_STORAGE_CHECK_RBD
LIBVIRT_STORAGE_CHECK_SHEEPDOG
LIBVIRT_STORAGE_CHECK_GLUSTER
LIBVIRT_STORAGE_CHECK_ZFS
LIBVIRT_STORAGE_CHECK_VSTORAGE

with_storage=no
for backend in dir fs lvm iscsi scsi mpath rbd disk; do
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

dnl
dnl check for kernel headers required by btrfs ioctl
dnl
if test "$with_linux" = "yes"; then
    AC_CHECK_HEADERS([linux/btrfs.h])
fi

dnl Allow perl/python overrides
AC_PATH_PROGS([PYTHON], [python2 python])
AC_PATH_PROG([PERL], [perl])
if test -z "$PERL"; then
         AC_MSG_ERROR([Failed to find perl.])
fi

LIBVIRT_ARG_WITH([TEST_SUITE], [build test suite by default], [check])
case "$with_test_suite" in
    yes|no|check) ;;
    *) AC_MSG_ERROR([bad value ${withval} for tests option]) ;;
esac

AC_MSG_CHECKING([Whether to build test suite by default])
if test "$with_test_suite" = "check" ; then
  if test -d $srcdir/.git ; then
    with_test_suite=yes
  else
    with_test_suite=no
  fi
fi
AC_MSG_RESULT([$with_test_suite])
AM_CONDITIONAL([WITH_TESTS], [test "$with_test_suite" = "yes"])

LIBVIRT_ARG_ENABLE([EXPENSIVE_TESTS],
                   [set the default for enabling expensive tests ]
                     [(gnulib and long timeouts), use VIR_TEST_EXPENSIVE to ]
                     [override during make],
                   [check])
case "$enable_expensive_tests" in
  0|no) VIR_TEST_EXPENSIVE_DEFAULT=0 ;;
  1|yes) VIR_TEST_EXPENSIVE_DEFAULT=1 ;;
  check) ;;
  *) AC_MSG_ERROR([bad value ${enable_expensive_tests} for enable-expensive-tests option]) ;;
esac
if test "$enable_expensive_tests" = check; then
  if test -d $srcdir/.git ; then
    VIR_TEST_EXPENSIVE_DEFAULT=0
  else
    VIR_TEST_EXPENSIVE_DEFAULT=1
  fi
fi
AC_SUBST([VIR_TEST_EXPENSIVE_DEFAULT])
AM_CONDITIONAL([WITH_EXPENSIVE_TESTS], [test $VIR_TEST_EXPENSIVE_DEFAULT = 1])

LIBVIRT_ARG_ENABLE([TEST_COVERAGE], [turn on code coverage instrumentation], [no])
case "$enable_test_coverage" in
  yes|no) ;;
  *) AC_MSG_ERROR([bad value ${enable_test_coverga} for test-coverage option]) ;;
esac

if test "$enable_test_coverage" = yes; then
  save_WARN_CFLAGS=$WARN_CFLAGS
  WARN_CFLAGS=
  gl_WARN_ADD([-fprofile-arcs])
  gl_WARN_ADD([-ftest-coverage])
  COVERAGE_FLAGS=$WARN_CFLAGS
  AC_SUBST([COVERAGE_CFLAGS], [$COVERAGE_FLAGS])
  AC_SUBST([COVERAGE_LDFLAGS], [$COVERAGE_FLAGS])
  WARN_CFLAGS=$save_WARN_CFLAGS
fi

LIBVIRT_ARG_ENABLE([TEST_OOM], [memory allocation failure checking], [no])
case "$enable_test_oom" in
  yes|no) ;;
  *) AC_MSG_ERROR([bad value ${enable_test_oom} for test-oom option]) ;;
esac

if test "$enable_test_oom" = yes; then
  have_trace=yes
  AC_CHECK_HEADER([execinfo.h],[],[have_trace=no])
  AC_CHECK_FUNC([backtrace],[],[have_trace=no])
  if test "$have_trace" = "yes"; then
    AC_DEFINE([TEST_OOM_TRACE], 1, [Whether backtrace() is available])
  fi
  AC_DEFINE([TEST_OOM], 1, [Whether malloc OOM checking is enabled])
fi

LIBVIRT_ARG_ENABLE([TEST_LOCKING], [thread locking tests using CIL], [no])
case "$enable_test_locking" in
  yes|no) ;;
  *) AC_MSG_ERROR([bad value ${enable_test_locking} for test-locking option]) ;;
esac

if test "$enable_test_locking" = "yes"; then
  LOCK_CHECKING_CFLAGS="-save-temps"
  AC_SUBST([LOCK_CHECKING_CFLAGS])
fi
AM_CONDITIONAL([WITH_CIL],[test "$enable_test_locking" = "yes"])

dnl Check for gettext - don't go any newer than what RHEL 5 supports
dnl
dnl save and restore CPPFLAGS around gettext check as the internal iconv
dnl check might leave -I/usr/local/include in CPPFLAGS on FreeBSD resulting
dnl in the build picking up previously installed libvirt/libvirt.h instead
dnl of the correct one from the source tree.
dnl compute the difference between save_CPPFLAGS and CPPFLAGS and append it
dnl to INCLUDES in order to preserve changes made by gettext but in a place
dnl that does not break the build
save_CPPFLAGS="$CPPFLAGS"
AM_GNU_GETTEXT_VERSION([0.17])
AM_GNU_GETTEXT([external])
GETTEXT_CPPFLAGS=
if test "x$save_CPPFLAGS" != "x$CPPFLAGS"; then
 set dummy $CPPFLAGS; shift
 for var
 do
   case " $var " in
     " $save_CPPFLAGS ") ;;
     *) GETTEXT_CPPFLAGS="$GETTEXT_CPPFLAGS $var" ;;
   esac
 done
fi
CPPFLAGS="$save_CPPFLAGS"
AC_SUBST([GETTEXT_CPPFLAGS])

ALL_LINGUAS=`cd "$srcdir/po" > /dev/null && ls *.po | sed 's+\.po$++'`

dnl Cygwin, MinGW and MSVC checks
LIBVIRT_WIN_CHECK_COMMON
LIBVIRT_WIN_CHECK_CYGWIN
LIBVIRT_WIN_CHECK_MINGW
LIBVIRT_WIN_CHECK_SYMBOLS
LIBVIRT_WIN_CHECK_WINDRES


dnl Driver-Modules library support
LIBVIRT_ARG_DRIVER_MODULES
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

dnl GET_VLAN_VID_CMD is required for virNetDevGetVLanID
AC_CHECK_DECLS([GET_VLAN_VID_CMD], [], [], [[#include <linux/if_vlan.h>]])

# Check for Linux vs. BSD ifreq members
AC_CHECK_MEMBERS([struct ifreq.ifr_newname,
                  struct ifreq.ifr_ifindex,
                  struct ifreq.ifr_index,
                  struct ifreq.ifr_hwaddr],
                 [], [],
                 [#include <sys/socket.h>
                  #include <net/if.h>
                 ])

# Check for BSD approach for setting MAC addr
AC_LINK_IFELSE([AC_LANG_PROGRAM(
     [[
        #include <sys/types.h>
        #include <sys/socket.h>
        #include <net/if_dl.h>
     ]],
     [[
        link_addr(0, 0)]])],
     [AC_DEFINE([HAVE_DECL_LINK_ADDR],
                [1],
                [whether link_addr is available])])

# Check for BSD approach for bridge management
AC_CHECK_DECLS([BRDGSFD, BRDGADD, BRDGDEL],
               [AC_DEFINE([HAVE_BSD_BRIDGE_MGMT],
                          [1],
                          [whether BSD style bridge management is available])],
               [],
               [#include <stdint.h>
                #include <net/if.h>
                #include <net/ethernet.h>
                #include <net/if_bridgevar.h>
               ])

# Check for BSD CPU affinity availability
AC_CHECK_DECLS([cpuset_getaffinity],
               [AC_DEFINE([HAVE_BSD_CPU_AFFINITY],
                          [1],
                          [whether BSD CPU affinity management is available])],
               [],
               [#include <sys/param.h>
                #include <sys/cpuset.h>
               ])

# Check for BSD kvm (kernel memory interface)
if test $with_freebsd = yes; then
     AC_CHECK_LIB([kvm], [kvm_getprocs], [],
                  [AC_MSG_ERROR([BSD kernel memory interface library is required to build on FreeBSD])]
                 )
fi

# FreeBSD 10-STABLE requires _IFI_OQDROPS to be defined for if_data.ifi_oqdrops
# field be available
old_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -D_IFI_OQDROPS"

AC_CHECK_MEMBERS([struct if_data.ifi_oqdrops],
		 [],
		 [CFLAGS="$old_CFLAGS"],
		 [#include <net/if.h>
		 ])

AC_CHECK_DECLS([clock_serv_t, host_get_clock_service, clock_get_time],
               [AC_DEFINE([HAVE_MACH_CLOCK_ROUTINES],
                          [1],
                          [whether Mach clock routines are available])],
               [],
               [#include <mach/clock.h>
                #include <mach/mach.h>
               ])

# Check if we need to look for ifconfig
if test "$want_ifconfig" = "yes"; then
     AC_PATH_PROG([IFCONFIG_PATH], [ifconfig])
     if test -z "$IFCONFIG_PATH"; then
         AC_MSG_ERROR([Failed to find ifconfig.])
     fi
     AC_DEFINE_UNQUOTED([IFCONFIG_PATH], "$IFCONFIG_PATH", [path to ifconfig binary])
fi

# Detect when running under the clang static analyzer's scan-build driver
# or Coverity-prevent's cov-build.  Define STATIC_ANALYSIS accordingly.
AC_CACHE_CHECK([whether this build is done by a static analysis tool],
  [lv_cv_static_analysis], [
    lv_cv_static_analysis=no
    if test -n "${CCC_ANALYZER_ANALYSIS+set}" || \
       test -n "$COVERITY_BUILD_COMMAND$COVERITY_LD_PRELOAD"; then
      lv_cv_static_analysis=yes
    fi
  ])
t=0
test "x$lv_cv_static_analysis" = xyes && t=1
AC_DEFINE_UNQUOTED([STATIC_ANALYSIS], [$t],
  [Define to 1 when performing static analysis.])

# Some GNULIB base64 symbols clash with a kerberos library
AC_DEFINE_UNQUOTED([isbase64],[libvirt_gl_isbase64],[Hack to avoid symbol clash])
AC_DEFINE_UNQUOTED([base64_encode],[libvirt_gl_base64_encode],[Hack to avoid symbol clash])
AC_DEFINE_UNQUOTED([base64_encode_alloc],[libvirt_gl_base64_encode_alloc],[Hack to avoid symbol clash])

AC_CONFIG_FILES([run],
                [chmod +x,-w run])
AC_CONFIG_FILES([\
        Makefile src/Makefile include/libvirt/Makefile docs/Makefile \
        gnulib/lib/Makefile \
        gnulib/tests/Makefile \
        libvirt.pc \
        libvirt-qemu.pc \
        libvirt-lxc.pc \
        libvirt-admin.pc \
        src/libvirt.pc \
        src/libvirt-qemu.pc \
        src/libvirt-lxc.pc \
        libvirt.spec mingw-libvirt.spec \
        po/Makefile.in \
        include/libvirt/libvirt-common.h \
        daemon/Makefile \
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
LIBVIRT_DRIVER_RESULT_XEN
LIBVIRT_DRIVER_RESULT_QEMU
LIBVIRT_DRIVER_RESULT_UML
LIBVIRT_DRIVER_RESULT_OPENVZ
LIBVIRT_DRIVER_RESULT_VMWARE
LIBVIRT_DRIVER_RESULT_VBOX
LIBVIRT_DRIVER_RESULT_XENAPI
LIBVIRT_DRIVER_RESULT_LIBXL
LIBVIRT_DRIVER_RESULT_LXC
LIBVIRT_DRIVER_RESULT_PHYP
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
LIBVIRT_RESULT_AVAHI
LIBVIRT_RESULT_BLKID
LIBVIRT_RESULT_CAPNG
LIBVIRT_RESULT_CURL
LIBVIRT_RESULT_DBUS
LIBVIRT_RESULT_DLOPEN
LIBVIRT_RESULT_FIREWALLD
LIBVIRT_RESULT_FUSE
LIBVIRT_RESULT_GLUSTER
LIBVIRT_RESULT_GNUTLS
LIBVIRT_RESULT_HAL
LIBVIRT_RESULT_LIBNL
LIBVIRT_RESULT_LIBPCAP
LIBVIRT_RESULT_LIBSSH
LIBVIRT_RESULT_LIBXL
LIBVIRT_RESULT_LIBXML
LIBVIRT_RESULT_MACVTAP
LIBVIRT_RESULT_NETCF
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
LIBVIRT_RESULT_XEN
LIBVIRT_RESULT_XENAPI
LIBVIRT_RESULT_YAJL
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Windows])
AC_MSG_NOTICE([])
LIBVIRT_WIN_RESULT_COMMON
LIBVIRT_WIN_RESULT_WINDRES
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Test suite])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([         Coverage: $enable_coverage])
AC_MSG_NOTICE([        Alloc OOM: $enable_oom])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Miscellaneous])
AC_MSG_NOTICE([])
LIBVIRT_RESULT_DEBUG
AC_MSG_NOTICE([       Use -Werror: $enable_werror])
AC_MSG_NOTICE([     Warning Flags: $WARN_CFLAGS])
LIBVIRT_RESULT_DTRACE
LIBVIRT_RESULT_NUMAD
LIBVIRT_RESULT_XML_CATALOG
LIBVIRT_RESULT_INIT_SCRIPT
LIBVIRT_RESULT_CHRDEV_LOCK_FILES
LIBVIRT_RESULT_DEFAULT_EDITOR
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
