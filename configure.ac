dnl Process this file with autoconf to produce a configure script.

dnl Copyright (C) 2005-2013 Red Hat, Inc.
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

AC_INIT([libvirt], [1.1.4], [libvir-list@redhat.com], [], [http://libvirt.org])
AC_CONFIG_SRCDIR([src/libvirt.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AH_BOTTOM([#include <config-post.h>])
AC_CONFIG_MACRO_DIR([m4])
dnl Make automake keep quiet about wildcards & other GNUmake-isms; also keep
dnl quiet about the fact that we intentionally cater to automake 1.9
AM_INIT_AUTOMAKE([-Wno-portability -Wno-obsolete tar-ustar subdir-objects])

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

AC_ARG_WITH([packager],
            [AS_HELP_STRING([--with-packager],
                            [Extra packager name])],
            [],[with_packager=no])
AC_ARG_WITH([packager-version],
            [AS_HELP_STRING([--with-packager-version],
                            [Extra packager version])],
            [],[with_packager_version=no])
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

dnl Required minimum versions of all libs we depend on
LIBXML_REQUIRED="2.6.0"
GNUTLS_REQUIRED="1.0.25"
POLKIT_REQUIRED="0.6"
PARTED_REQUIRED="1.8.0"
DEVMAPPER_REQUIRED=1.0.0
LIBPCAP_REQUIRED="1.0.0"
LIBNL_REQUIRED="1.1"

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
VERSION_SCRIPT_FLAGS=-Wl,--version-script=
`$LD --help 2>&1 | grep -- --version-script >/dev/null` || \
    VERSION_SCRIPT_FLAGS="-Wl,-M -Wl,"
AC_MSG_RESULT([$VERSION_SCRIPT_FLAGS])

dnl Specify if we rely on ifconfig instead of iproute2 (e.g. in case
dnl we're working on BSD)
want_ifconfig=no

dnl Make some notes about which OS we're compiling for, as the lxc and qemu
dnl drivers require linux headers, and storage_mpath, dtrace, and nwfilter
dnl are also linux specific.  The "network" and storage_fs drivers are known
dnl to not work on MacOS X presently, so we also make a note if compiling
dnl for that

with_linux=no with_osx=no with_freebsd=no
case $host in
  *-*-linux*) with_linux=yes ;;
  *-*-darwin*) with_osx=yes ;;
  *-*-freebsd*) with_freebsd=yes ;;
esac

if test $with_linux = no; then
    if test "x$with_lxc" != xyes
    then
        with_lxc=no
    fi
    with_dtrace=no
fi

if test $with_freebsd = yes; then
   want_ifconfig=yes

   with_firewalld=no
fi

AM_CONDITIONAL([WITH_LINUX], [test "$with_linux" = "yes"])
AM_CONDITIONAL([WITH_FREEBSD], [test "$with_freebsd" = "yes"])

# The daemon requires remote support.  Likewise, if we are not using
# RPC, we don't need several libraries.
if test "$with_remote" = "no" ; then
  with_libvirtd=no
  with_gnutls=no
  with_ssh2=no
  with_sasl=no
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

LIBVIRT_CHECK_APPARMOR
LIBVIRT_CHECK_ATTR
LIBVIRT_CHECK_AUDIT
LIBVIRT_CHECK_AVAHI
LIBVIRT_CHECK_BLKID
LIBVIRT_CHECK_CAPNG
LIBVIRT_CHECK_CURL
LIBVIRT_CHECK_DBUS
LIBVIRT_CHECK_FUSE
LIBVIRT_CHECK_GLUSTER
LIBVIRT_CHECK_HAL
LIBVIRT_CHECK_NETCF
LIBVIRT_CHECK_NUMACTL
LIBVIRT_CHECK_OPENWSMAN
LIBVIRT_CHECK_PCIACCESS
LIBVIRT_CHECK_READLINE
LIBVIRT_CHECK_SANLOCK
LIBVIRT_CHECK_SASL
LIBVIRT_CHECK_SELINUX
LIBVIRT_CHECK_SSH2
LIBVIRT_CHECK_UDEV
LIBVIRT_CHECK_YAJL

AC_MSG_CHECKING([for CPUID instruction])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
  [[
    #include <stdint.h>
  ]],
  [[
    uint32_t eax, ebx, ecx, edx;
    asm volatile (
        "cpuid"
        : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
        : "a" (eax));
  ]])],
  [have_cpuid=yes],
  [have_cpuid=no])
if test "x$have_cpuid" = xyes; then
  AC_DEFINE_UNQUOTED([HAVE_CPUID], 1, [whether CPUID instruction is supported])
fi
AC_MSG_RESULT([$have_cpuid])

AC_CHECK_SIZEOF([long])

dnl Availability of various common functions (non-fatal if missing),
dnl and various less common threadsafe functions
AC_CHECK_FUNCS_ONCE([cfmakeraw fallocate geteuid getgid getgrnam_r \
  getmntent_r getpwuid_r getuid kill mmap newlocale posix_fallocate \
  posix_memalign prlimit regexec sched_getaffinity setgroups setns \
  setrlimit symlink sysctlbyname])

dnl Availability of pthread functions (if missing, win32 threading is
dnl assumed).  Because of $LIB_PTHREAD, we cannot use AC_CHECK_FUNCS_ONCE.
dnl LIB_PTHREAD and LIBMULTITHREAD were set during gl_INIT by gnulib.
old_LIBS=$LIBS
LIBS="$LIBS $LIB_PTHREAD $LIBMULTITHREAD"
AC_CHECK_FUNCS([pthread_mutexattr_init])
LIBS=$old_libs

dnl Availability of various common headers (non-fatal if missing).
AC_CHECK_HEADERS([pwd.h paths.h regex.h sys/un.h \
  sys/poll.h syslog.h mntent.h net/ethernet.h linux/magic.h \
  sys/un.h sys/syscall.h sys/sysctl.h netinet/tcp.h ifaddrs.h \
  libtasn1.h sys/ucred.h sys/mount.h])
dnl Check whether endian provides handy macros.
AC_CHECK_DECLS([htole64], [], [], [[#include <endian.h>]])

dnl We need to decide at configure time if libvirt will use real atomic
dnl operations ("lock free") or emulated ones with a mutex.

dnl Note that the atomic ops are only available with GCC on x86 when
dnl using -march=i486 or higher.  If we detect that the atomic ops are
dnl not available but would be available given the right flags, we want
dnl to abort and advise the user to fix their CFLAGS.  It's better to do
dnl that then to silently fall back on emulated atomic ops just because
dnl the user had the wrong build environment.

atomic_ops=

AC_MSG_CHECKING([for atomic ops implementation])

AC_TRY_COMPILE([], [__GCC_HAVE_SYNC_COMPARE_AND_SWAP_4;],[
  atomic_ops=gcc
],[])

if test "$atomic_ops" = "" ; then
  SAVE_CFLAGS="${CFLAGS}"
  CFLAGS="-march=i486"
  AC_TRY_COMPILE([],
                 [__GCC_HAVE_SYNC_COMPARE_AND_SWAP_4;],
                 [AC_MSG_ERROR([Libvirt must be built with -march=i486 or later.])],
                 [])
  CFLAGS="${SAVE_CFLAGS}"

  case "$host" in
    *-*-mingw* | *-*-msvc* )
      atomic_ops=win32
      ;;
    *)
      if test "$ac_cv_header_pthread_h" = "yes" ; then
        atomic_ops=pthread
      else
        AC_MSG_ERROR([Libvirt must be built with GCC or have pthread.h on non-Win32 platforms])
      fi
      ;;
  esac
fi

case "$atomic_ops" in
   gcc)
     AC_DEFINE([VIR_ATOMIC_OPS_GCC],[1],[Use GCC atomic ops])
     ;;
   win32)
     AC_DEFINE([VIR_ATOMIC_OPS_WIN32],[1],[Use Win32 atomic ops])
     ;;
   pthread)
     AC_DEFINE([VIR_ATOMIC_OPS_PTHREAD],[1],[Use pthread atomic ops emulation])
     ;;
esac
AM_CONDITIONAL([WITH_ATOMIC_OPS_PTHREAD],[test "$atomic_ops" = "pthread"])
AC_MSG_RESULT([$atomic_ops])


AC_CHECK_TYPE([struct ifreq],
  [AC_DEFINE([HAVE_STRUCT_IFREQ],[1],
    [Defined if struct ifreq exists in net/if.h])],
  [], [[#include <sys/socket.h>
        #include <net/if.h>
  ]])

dnl Our only use of libtasn1.h is in the testsuite, and can be skipped
dnl if the header is not present.  Assume -ltasn1 is present if the
dnl header could be found.
AM_CONDITIONAL([HAVE_LIBTASN1], [test "x$ac_cv_header_libtasn1_h" = "xyes"])

AC_CHECK_LIB([intl],[gettext],[])

dnl Do we have rpcgen?
AC_PATH_PROG([RPCGEN], [rpcgen], [no])
AM_CONDITIONAL([HAVE_RPCGEN], [test "x$ac_cv_path_RPCGEN" != "xno"])
dnl Is this GLIBC's buggy rpcgen?
AM_CONDITIONAL([HAVE_GLIBC_RPCGEN],
	       [test "x$ac_cv_path_RPCGEN" != "xno" &&
	        $ac_cv_path_RPCGEN -t </dev/null >/dev/null 2>&1])

dnl Miscellaneous external programs.
AC_PATH_PROG([XMLLINT], [xmllint], [/usr/bin/xmllint])
AC_PATH_PROG([XMLCATALOG], [xmlcatalog], [/usr/bin/xmlcatalog])
AC_PATH_PROG([XSLTPROC], [xsltproc], [/usr/bin/xsltproc])
AC_PATH_PROG([AUGPARSE], [augparse], [/usr/bin/augparse])
AC_PROG_MKDIR_P

dnl External programs that we can use if they are available.
dnl We will hard-code paths to these programs unless we cannot
dnl detect them, in which case we'll search for the program
dnl along the $PATH at runtime and fail if it's not there.
AC_PATH_PROG([DNSMASQ], [dnsmasq], [dnsmasq],
	[/sbin:/usr/sbin:/usr/local/sbin:$PATH])
AC_PATH_PROG([RADVD], [radvd], [radvd],
	[/sbin:/usr/sbin:/usr/local/sbin:$PATH])
AC_PATH_PROG([TC], [tc], [tc],
    [/sbin:/usr/sbin:/usr/local/sbin:$PATH])
AC_PATH_PROG([UDEVADM], [udevadm], [],
	[/sbin:/usr/sbin:/usr/local/sbin:$PATH])
AC_PATH_PROG([UDEVSETTLE], [udevsettle], [],
	[/sbin:/usr/sbin:/usr/local/sbin:$PATH])
AC_PATH_PROG([MODPROBE], [modprobe], [modprobe],
	[/sbin:/usr/sbin:/usr/local/sbin:$PATH])
AC_PATH_PROG([OVSVSCTL], [ovs-vsctl], [ovs-vsctl],
	[/sbin:/usr/sbin:/usr/local/sbin:$PATH])
AC_PATH_PROG([SCRUB], [scrub], [scrub],
	[/sbin:/usr/sbin:/usr/local/sbin:$PATH])

AC_DEFINE_UNQUOTED([DNSMASQ],["$DNSMASQ"],
        [Location or name of the dnsmasq program])
AC_DEFINE_UNQUOTED([RADVD],["$RADVD"],
        [Location or name of the radvd program])
AC_DEFINE_UNQUOTED([TC],["$TC"],
        [Location or name of the tc profram (see iproute2)])
AC_DEFINE_UNQUOTED([OVSVSCTL],["$OVSVSCTL"],
        [Location or name of the ovs-vsctl program])

if test -n "$UDEVADM"; then
  AC_DEFINE_UNQUOTED([UDEVADM],["$UDEVADM"],
        [Location or name of the udevadm program])
fi
if test -n "$UDEVSETTLE"; then
  AC_DEFINE_UNQUOTED([UDEVSETTLE],["$UDEVSETTLE"],
        [Location or name of the udevsettle program])
fi
if test -n "$MODPROBE"; then
  AC_DEFINE_UNQUOTED([MODPROBE],["$MODPROBE"],
        [Location or name of the modprobe program])
fi
AC_DEFINE_UNQUOTED([SCRUB],["$SCRUB"],
        [Location or name of the scrub program (for wiping algorithms)])

dnl Specific dir for HTML output ?
AC_ARG_WITH([html-dir], [AS_HELP_STRING([--with-html-dir=path],
            [path to base html directory, default $datadir/doc/html])],
            [HTML_DIR=$withval], [HTML_DIR='$(datadir)/doc'])

AC_ARG_WITH([html-subdir], [AS_HELP_STRING([--with-html-subdir=path],
            [directory used under html-dir, default $PACKAGE-$VERSION/html])],
            [test "x$withval" != "x" && HTML_DIR="$HTML_DIR/$withval"],
            [HTML_DIR="$HTML_DIR/\$(PACKAGE)-\$(VERSION)/html"])
AC_SUBST([HTML_DIR])

dnl Specific XML catalog file for validation of generated html
AC_ARG_WITH([xml-catalog-file],
            [AS_HELP_STRING([--with-xml-catalog-file=path],
                [path to XML catalog file for validating
                 generated html, default /etc/xml/catalog])],
            [XML_CATALOG_FILE=$withval],
            [XML_CATALOG_FILE='/etc/xml/catalog'])
AC_SUBST([XML_CATALOG_FILE])

dnl if --prefix is /usr, don't use /usr/var for localstatedir
dnl or /usr/etc for sysconfdir
dnl as this makes a lot of things break in testing situations

if test "$prefix" = "/usr" && test "$localstatedir" = '${prefix}/var' ; then
    localstatedir='/var'
fi
if test "$prefix" = "/usr" && test "$sysconfdir" = '${prefix}/etc' ; then
    sysconfdir='/etc'
fi

dnl Allow to build without Xen, QEMU/KVM, test or remote driver
AC_ARG_WITH([xen],
  [AS_HELP_STRING([--with-xen],
    [add XEN support @<:@default=check@:>@])])
m4_divert_text([DEFAULTS], [with_xen=check])
AC_ARG_WITH([xen-inotify],
  [AS_HELP_STRING([--with-xen-inotify],
    [add XEN inotify support @<:@default=check@:>@])])
m4_divert_text([DEFAULTS], [with_xen_inotify=check])
AC_ARG_WITH([qemu],
  [AS_HELP_STRING([--with-qemu],
    [add QEMU/KVM support @<:@default=yes@:>@])])
m4_divert_text([DEFAULTS], [with_qemu=yes])
AC_ARG_WITH([uml],
  [AS_HELP_STRING([--with-uml],
    [add UML support @<:@default=check@:>@])])
m4_divert_text([DEFAULTS], [with_uml=check])
AC_ARG_WITH([openvz],
  [AS_HELP_STRING([--with-openvz],
    [add OpenVZ support @<:@default=check@:>@])])
m4_divert_text([DEFAULTS], [with_openvz=check])
AC_ARG_WITH([vmware],
  [AS_HELP_STRING([--with-vmware],
    [add VMware support @<:@default=yes@:>@])])
m4_divert_text([DEFAULTS], [with_vmware=yes])
AC_ARG_WITH([phyp],
  [AS_HELP_STRING([--with-phyp],
    [add PHYP support @<:@default=check@:>@])])
m4_divert_text([DEFAULTS], [with_phyp=check])
AC_ARG_WITH([xenapi],
  [AS_HELP_STRING([--with-xenapi],
    [add XenAPI support @<:@default=check@:>@])])
m4_divert_text([DEFAULTS], [with_xenapi=check])
AC_ARG_WITH([libxl],
  [AS_HELP_STRING([--with-libxl],
    [add libxenlight support @<:@default=check@:>@])])
m4_divert_text([DEFAULTS], [with_libxl=check])
AC_ARG_WITH([vbox],
  [AS_HELP_STRING([--with-vbox=@<:@PFX@:>@],
    [VirtualBox XPCOMC location @<:@default=yes@:>@])])
m4_divert_text([DEFAULTS], [with_vbox=yes])
AC_ARG_WITH([lxc],
  [AS_HELP_STRING([--with-lxc],
    [add Linux Container support @<:@default=check@:>@])])
m4_divert_text([DEFAULTS], [with_lxc=check])
AC_ARG_WITH([esx],
  [AS_HELP_STRING([--with-esx],
    [add ESX support @<:@default=check@:>@])])
m4_divert_text([DEFAULTS], [with_esx=check])
AC_ARG_WITH([hyperv],
  [AS_HELP_STRING([--with-hyperv],
    [add Hyper-V support @<:@default=check@:>@])])
m4_divert_text([DEFAULTS], [with_hyperv=check])
AC_ARG_WITH([parallels],
  [AS_HELP_STRING([--with-parallels],
    [add Parallels Cloud Server support @<:@default=check@:>@])])
m4_divert_text([DEFAULTS], [with_parallels=check])
AC_ARG_WITH([test],
  [AS_HELP_STRING([--with-test],
    [add test driver support @<:@default=yes@:>@])])
m4_divert_text([DEFAULTS], [with_test=yes])
AC_ARG_WITH([remote],
  [AS_HELP_STRING([--with-remote],
    [add remote driver support @<:@default=yes@:>@])])
m4_divert_text([DEFAULTS], [with_remote=yes])
AC_ARG_WITH([libvirtd],
  [AS_HELP_STRING([--with-libvirtd],
    [add libvirtd support @<:@default=yes@:>@])])
m4_divert_text([DEFAULTS], [with_libvirtd=yes])
AC_ARG_WITH([chrdev-lock-files],
  [AS_HELP_STRING([--with-chrdev-lock-files],
    [location for UUCP style lock files for character devices
     (use auto for default paths on some platforms) @<:@default=auto@:>@])])
m4_divert_text([DEFAULTS], [with_chrdev_lock_files=auto])

dnl
dnl in case someone want to build static binaries
dnl STATIC_BINARIES="-static"
dnl
STATIC_BINARIES=
AC_SUBST([STATIC_BINARIES])

dnl --enable-debug=(yes|no)
AC_ARG_ENABLE([debug],
              [AS_HELP_STRING([--enable-debug=@<:@no|yes@:>@],
                             [enable debugging output @<:@default=yes@:>@])],
  [],[enable_debug=yes])
AM_CONDITIONAL([ENABLE_DEBUG], test x"$enable_debug" = x"yes")
if test x"$enable_debug" = x"yes"; then
   AC_DEFINE([ENABLE_DEBUG], [], [whether debugging is enabled])
fi



dnl
dnl init script flavor
dnl
AC_MSG_CHECKING([for init script flavor])
AC_ARG_WITH([init-script],
  [AS_HELP_STRING([--with-init-script@<:@=STYLE@:>@],
    [Style of init script to install: redhat, systemd, systemd+redhat,
     upstart, check, none @<:@default=check@:>@])],
  [],[with_init_script=check])
init_redhat=no
init_systemd=no
init_upstart=no
case "$with_init_script" in
    systemd+redhat)
       init_redhat=yes
       init_systemd=yes
       ;;
    systemd)
       init_systemd=yes
       ;;
    upstart)
       init_upstart=yes
       ;;
    redhat)
       init_redhat=yes
       ;;
    none)
       ;;
    check)
       if test "$cross_compiling" != yes && test -f /etc/redhat-release; then
          init_redhat=yes
          with_init_script=redhat
       fi
       ;;
    *)
       AC_MSG_ERROR([Unknown initscript flavour $with_init_script])
    ;;
esac
AM_CONDITIONAL([LIBVIRT_INIT_SCRIPT_RED_HAT], test "$init_redhat" = "yes")
AM_CONDITIONAL([LIBVIRT_INIT_SCRIPT_UPSTART], test "$init_upstart" = "yes")
AM_CONDITIONAL([LIBVIRT_INIT_SCRIPT_SYSTEMD], test "$init_systemd" = "yes")
AC_MSG_RESULT($with_init_script)


AC_MSG_CHECKING([for whether to install sysctl config])
AC_ARG_WITH([sysctl],
            [AS_HELP_STRING([--with-sysctl@<:@=yes/no@:>@],
               [Whether to install sysctl configs @<:@default=check@:>@])],
            [],[with_sysctl=check])

if test "$with_sysctl" = "yes" || test "$with_sysctl" = "check"
then
  case $host in
    *-*-linux*)
      with_sysctl=yes
      ;;
    **)
      if test "$with_sysctl" = "yes"; then
         AC_MSG_ERROR([No sysctl configuration supported for $host])
      else
         with_sysctl=no
      fi
      ;;
  esac
fi
AM_CONDITIONAL([WITH_SYSCTL], test "$with_sysctl" = "yes")
AC_MSG_RESULT($with_sysctl)

dnl RHEL-5 has a peculiar version of Xen, which requires some special casing
AC_ARG_WITH([rhel5-api],
	[AS_HELP_STRING([--with-rhel5-api=@<:@ARG@:>@],
		[build for the RHEL-5 API @<:@default=no@:>@])])
if test x"$with_rhel5_api" = x"yes"; then
   AC_DEFINE([WITH_RHEL5_API], [1], [whether building for the RHEL-5 API])
fi

AC_PATH_PROG([IP_PATH], [ip], /sbin/ip, [/usr/sbin:$PATH])
AC_DEFINE_UNQUOTED([IP_PATH], "$IP_PATH", [path to ip binary])

AC_PATH_PROG([IPTABLES_PATH], [iptables], /sbin/iptables, [/usr/sbin:$PATH])
AC_DEFINE_UNQUOTED([IPTABLES_PATH], "$IPTABLES_PATH", [path to iptables binary])

AC_PATH_PROG([IP6TABLES_PATH], [ip6tables], /sbin/ip6tables, [/usr/sbin:$PATH])
AC_DEFINE_UNQUOTED([IP6TABLES_PATH], "$IP6TABLES_PATH", [path to ip6tables binary])

AC_PATH_PROG([EBTABLES_PATH], [ebtables], /sbin/ebtables, [/usr/sbin:$PATH])
AC_DEFINE_UNQUOTED([EBTABLES_PATH], "$EBTABLES_PATH", [path to ebtables binary])


dnl
dnl Checks for the OpenVZ driver
dnl

if test "$with_openvz" = "check"; then
    with_openvz=$with_linux
fi

if test "$with_openvz" = "yes" && test "$with_linux" = "no"; then
    AC_MSG_ERROR([The OpenVZ driver can be enabled on Linux only.])
fi

if test "$with_openvz" = "yes"; then
    AC_DEFINE_UNQUOTED([WITH_OPENVZ], 1, [whether OpenVZ driver is enabled])
fi
AM_CONDITIONAL([WITH_OPENVZ], [test "$with_openvz" = "yes"])


dnl
dnl Checks for the VMware Workstation/Player driver
dnl

if test "$with_vmware" = "yes"; then
    AC_DEFINE_UNQUOTED([WITH_VMWARE], 1, [whether VMware driver is enabled])
fi
AM_CONDITIONAL([WITH_VMWARE], [test "$with_vmware" = "yes"])


dnl
dnl check for XDR
dnl

if test x"$with_remote" = x"yes" || test x"$with_libvirtd" = x"yes"; then
    dnl Where are the XDR functions?
    dnl If portablexdr is installed, prefer that.
    dnl Otherwise try -lrpc (Cygwin) -lxdr (some MinGW), -lnsl (Solaris)
    dnl -ltirpc (glibc 2.13.90 or newer) or none (most Unix)
    AC_CHECK_LIB([portablexdr],[xdrmem_create],[],[
        AC_SEARCH_LIBS([xdrmem_create],[rpc xdr nsl tirpc],[],
            [AC_MSG_ERROR([Cannot find a XDR library])])
        ])

    dnl check for cygwin's variation in xdr function names
    AC_CHECK_FUNCS([xdr_u_int64_t],[],[],[#include <rpc/xdr.h>])

    dnl Cygwin/recent glibc requires -I/usr/include/tirpc for <rpc/rpc.h>
    old_CFLAGS=$CFLAGS
    AC_CACHE_CHECK([where to find <rpc/rpc.h>], [lv_cv_xdr_cflags], [
      for add_CFLAGS in '' '-I/usr/include/tirpc' 'missing'; do
        if test x"$add_CFLAGS" = xmissing; then
          lv_cv_xdr_cflags=missing; break
        fi
        CFLAGS="$old_CFLAGS $add_CFLAGS"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <rpc/rpc.h>
        ]])], [lv_cv_xdr_cflags=${add_CFLAGS:-none}; break])
      done
    ])
    CFLAGS=$old_CFLAGS
    case $lv_cv_xdr_cflags in
      none) XDR_CFLAGS= ;;
      missing) AC_MSG_ERROR([Unable to find <rpc/rpc.h>]) ;;
      *) XDR_CFLAGS=$lv_cv_xdr_cflags ;;
    esac
    AC_SUBST([XDR_CFLAGS])
fi


dnl
dnl check for libdl
dnl

dlfcn_found=yes
dlopen_found=yes

AC_CHECK_HEADER([dlfcn.h],, [dlfcn_found=no])
AC_SEARCH_LIBS([dlopen], [dl],, [dlopen_found=no])

case $ac_cv_search_dlopen:$host_os in
  'none required'* | *:mingw* | *:msvc*) DLOPEN_LIBS= ;;
  no*) AC_MSG_ERROR([Unable to find dlopen()]) ;;
  *) if test "x$dlfcn_found" != "xyes"; then
       AC_MSG_ERROR([Unable to find dlfcn.h])
     fi
     DLOPEN_LIBS=$ac_cv_search_dlopen ;;
esac

AC_SUBST([DLOPEN_LIBS])


dnl
dnl check for VirtualBox XPCOMC location
dnl

vbox_xpcomc_dir=

if test "x$with_vbox" != "xyes" && test "x$with_vbox" != "xno"; then
    # intentionally don't do any further checks here on the provided path
    vbox_xpcomc_dir=$with_vbox
    with_vbox=yes
fi

AC_DEFINE_UNQUOTED([VBOX_XPCOMC_DIR], ["$vbox_xpcomc_dir"],
                   [Location of directory containing VirtualBox XPCOMC library])

if test "x$with_vbox" = "xyes"; then
    AC_DEFINE_UNQUOTED([WITH_VBOX], 1, [whether VirtualBox driver is enabled])
fi
AM_CONDITIONAL([WITH_VBOX], [test "$with_vbox" = "yes"])

if test "$with_qemu" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_QEMU], 1, [whether QEMU driver is enabled])
fi
AM_CONDITIONAL([WITH_QEMU], [test "$with_qemu" = "yes"])

if test "$with_test" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_TEST], 1, [whether Test driver is enabled])
fi
AM_CONDITIONAL([WITH_TEST], [test "$with_test" = "yes"])

if test "$with_remote" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_REMOTE], 1, [whether Remote driver is enabled])
fi
AM_CONDITIONAL([WITH_REMOTE], [test "$with_remote" = "yes"])

if test "$with_libvirtd" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_LIBVIRTD], 1, [whether libvirtd daemon is enabled])
fi
AM_CONDITIONAL([WITH_LIBVIRTD], [test "$with_libvirtd" = "yes"])


old_LIBS="$LIBS"
old_CFLAGS="$CFLAGS"
LIBXENSERVER_LIBS=""
LIBXENSERVER_CFLAGS=""
dnl search for the XenServer library
fail=0
if test "$with_xenapi" != "no" ; then
    if test "$with_xenapi" != "yes" && test "$with_xenapi" != "check" ; then
        LIBXENSERVER_CFLAGS="-I$with_xenapi/include"
        LIBXENSERVER_LIBS="-L$with_xenapi"
    fi
    CFLAGS="$CFLAGS $LIBXENSERVER_CFLAGS"
    LIBS="$LIBS $LIBXENSERVER_LIBS"
    AC_CHECK_LIB([xenserver], [xen_vm_start], [
        LIBXENSERVER_LIBS="$LIBXENSERVER_LIBS -lxenserver"
    ],[
        if test "$with_xenapi" = "yes"; then
            fail=1
        fi
        with_xenapi=no
    ])
    if test "$with_xenapi" != "no" ; then
        if test "$with_curl" = "no"; then
            if test "$with_xenapi" = "yes"; then
                fail=1
            fi
            with_xenapi=no
        else
            with_xenapi=yes
        fi
    fi
fi

LIBS="$old_LIBS"
CFLAGS="$old_CFLAGS"

if test $fail = 1; then
    AC_MSG_ERROR([You must install libxenserver and libcurl to compile the XenAPI driver])
fi

if test "$with_xenapi" = "yes"; then
    AC_DEFINE_UNQUOTED([WITH_XENAPI], 1, [whether XenAPI driver is enabled])
fi

AC_SUBST([LIBXENSERVER_CFLAGS])
AC_SUBST([LIBXENSERVER_LIBS])

old_LIBS="$LIBS"
old_CFLAGS="$CFLAGS"
LIBXL_LIBS=""
LIBXL_CFLAGS=""
dnl search for libxl, aka libxenlight
fail=0
if test "$with_libxl" != "no" ; then
    if test "$with_libxl" != "yes" && test "$with_libxl" != "check" ; then
        LIBXL_CFLAGS="-I$with_libxl/include"
        LIBXL_LIBS="-L$with_libxl"
    fi
    CFLAGS="$CFLAGS $LIBXL_CFLAGS"
    LIBS="$LIBS $LIBXL_LIBS"
    AC_CHECK_LIB([xenlight], [libxl_ctx_alloc], [
        with_libxl=yes
        LIBXL_LIBS="$LIBXL_LIBS -lxenlight -lxenctrl"
    ],[
        if test "$with_libxl" = "yes"; then
            fail=1
        fi
        with_libxl=no
    ])
fi

LIBS="$old_LIBS"
CFLAGS="$old_CFLAGS"

if test $fail = 1; then
    AC_MSG_ERROR([You must install the libxl Library from Xen >= 4.2 to compile libxenlight driver with -lxl])
fi

if test "$with_libxl" = "yes"; then
    AC_DEFINE_UNQUOTED([WITH_LIBXL], 1, [whether libxenlight driver is enabled])
fi
AM_CONDITIONAL([WITH_LIBXL], [test "$with_libxl" = "yes"])

AC_SUBST([LIBXL_CFLAGS])
AC_SUBST([LIBXL_LIBS])

old_LIBS="$LIBS"
old_CFLAGS="$CFLAGS"
XEN_LIBS=""
XEN_CFLAGS=""
dnl search for the Xen store library
if test "$with_xen" != "no" ; then
    if test "$with_xen" != "yes" && test "$with_xen" != "check" ; then
        XEN_CFLAGS="-I$with_xen/include"
        XEN_LIBS="-L$with_xen/lib64 -L$with_xen/lib"
    fi
    fail=0
    CFLAGS="$CFLAGS $XEN_CFLAGS"
    LIBS="$LIBS $XEN_LIBS"
    AC_CHECK_LIB([xenstore], [xs_read], [
           with_xen=yes
           XEN_LIBS="$XEN_LIBS -lxenstore"
       ],[
           if test "$with_xen" = "yes"; then
               fail=1
           fi
           with_xen=no
       ])
fi

if test "$with_xen" != "no" ; then
    dnl In Xen 4.2, xs.h is deprecated in favor of xenstore.h.
    AC_CHECK_HEADERS([xenstore.h])
    AC_CHECK_HEADERS([xen/xen.h xen/version.h xen/dom0_ops.h],,[
       if test "$with_xen" = "yes"; then
           fail=1
       fi
       with_xen=no
    ],
[#include <stdio.h>
#include <stdint.h>
])
fi

if test "$with_xen" != "no" ; then
    dnl Search for the location of <xen/{linux,sys}/privcmd.h>.
    found=
    AC_CHECK_HEADERS([xen/sys/privcmd.h xen/linux/privcmd.h], [found=yes; break;], [],
       [#include <stdio.h>
        #include <stdint.h>
        #include <xen/xen.h>
       ])
    if test "x$found" != "xyes"; then
        if test "$with_xen" = "yes"; then
            fail=1
        fi
        with_xen=no
    fi
fi

LIBS="$old_LIBS"
CFLAGS="$old_CFLAGS"

if test $fail = 1; then
    AC_MSG_ERROR([You must install the Xen development package to compile Xen driver with -lxenstore])
fi

if test "$with_xen" = "yes"; then
    AC_DEFINE_UNQUOTED([WITH_XEN], 1, [whether Xen driver is enabled])
fi

AM_CONDITIONAL([WITH_XEN], [test "$with_xen" = "yes"])
AC_SUBST([XEN_CFLAGS])
AC_SUBST([XEN_LIBS])

AM_CONDITIONAL([WITH_XENXS], [test "$with_libxl" = "yes" || test "$with_xen" = "yes"])

dnl
dnl check for kernel headers required by xen_inotify
dnl
if test "$with_xen" != "yes"; then
    with_xen_inotify=no
fi
if test "$with_xen_inotify" != "no"; then
    AC_CHECK_HEADER([sys/inotify.h], [
        with_xen_inotify=yes
    ], [
        if test "$with_xen_inotify" = "check"; then
            with_xen_inotify=no
            AC_MSG_NOTICE([Header file <sys/inotify.h> is required for Xen Inotify support, disabling it])
        else
            AC_MSG_ERROR([Header file <sys/inotify.h> is required for Xen Inotify support!])
        fi
    0])
fi
if test "$with_xen_inotify" = "yes"; then
    AC_DEFINE_UNQUOTED([WITH_XEN_INOTIFY], 1,[whether Xen inotify sub-driver is enabled])
fi
AM_CONDITIONAL([WITH_XEN_INOTIFY], [test "$with_xen_inotify" = "yes"])

dnl
dnl check for kvm headers
dnl
AC_CHECK_HEADERS([linux/kvm.h])

dnl
dnl check for sufficient headers for LXC
dnl
if test "$with_libvirtd" = "no" ; then
  with_lxc=no
fi
if test "$with_lxc" = "yes" || test "$with_lxc" = "check"; then
    AC_LINK_IFELSE([AC_LANG_PROGRAM(
    [[
        #include <sched.h>
        #include <linux/loop.h>
        #include <sys/epoll.h>
    ]], [[
        unshare(!(LO_FLAGS_AUTOCLEAR + EPOLL_CLOEXEC));
    ]])], [
        with_lxc=yes
       AC_DEFINE([HAVE_DECL_LO_FLAGS_AUTOCLEAR], [1],
         [Define to 1 if you have the declaration of `LO_FLAGS_AUTOCLEAR',
         and to 0 if you don't.])
    ], [
        if test "$with_lxc" = "check"; then
            with_lxc=no
            AC_MSG_NOTICE([Required kernel features were not found, disabling LXC])
        else
            AC_MSG_ERROR([Required kernel features for LXC were not found])
        fi
    ])
    AC_LINK_IFELSE([AC_LANG_PROGRAM(
    [[
        #include <sched.h>
        #include <linux/loop.h>
        #include <sys/epoll.h>
    ]], [[
        unshare(!(LOOP_CTL_GET_FREE));
    ]])], [
       AC_DEFINE([HAVE_DECL_LOOP_CTL_GET_FREE], [1],
         [Define to 1 if you have the declaration of `LOOP_CTL_GET_FREE',
         and to 0 if you don't.])
    ])
fi
if test "$with_lxc" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_LXC], 1, [whether LXC driver is enabled])
fi
AM_CONDITIONAL([WITH_LXC], [test "$with_lxc" = "yes"])

dnl
dnl Checks for the Parallels driver
dnl

if test "$with_parallels" = "check"; then
    with_parallels=$with_linux
    if test ! $host_cpu = 'x86_64'; then
        with_parallels=no
    fi
fi

if test "$with_parallels" = "yes" && test "$with_linux" = "no"; then
    AC_MSG_ERROR([The Parallels driver can be enabled on Linux only.])
fi

if test "$with_parallels" = "yes"; then
    AC_DEFINE_UNQUOTED([WITH_PARALLELS], 1, [whether Parallels driver is enabled])
fi
AM_CONDITIONAL([WITH_PARALLELS], [test "$with_parallels" = "yes"])

dnl
dnl check for shell that understands <> redirection without truncation,
dnl needed by src/qemu/qemu_monitor_{text,json}.c.
dnl
if test "$with_qemu" = yes; then
  lv_wrapper_shell=
  AC_CACHE_CHECK([for shell that supports <> redirection],
    [lv_cv_wrapper_shell],
    [
    # If cross-compiling, guess that /bin/sh is good enough except for
    # Linux, where it might be dash 0.5.5 which is known broken; and on
    # Linux, we have a good chance that /bin/bash will exist.
    # If we guess wrong, a user can override the cache variable.
    # Going through /bin/bash is a slight slowdown if /bin/sh works.
    if test "$cross_compiling" = yes; then
      case $host_os in
        linux*) lv_cv_wrapper_shell=/bin/bash ;;
        *) lv_cv_wrapper_shell=/bin/sh ;;
      esac
    else
      for lv_cv_wrapper_shell in /bin/sh bash ksh zsh none; do
        test $lv_cv_wrapper_shell = none &&
          AC_MSG_ERROR([could not find decent shell])
        echo a > conftest.a
        ($lv_cv_wrapper_shell -c ': 1<>conftest.a') 2>/dev/null &&
        case `cat conftest.a`.$lv_cv_wrapper_shell in
          a./*) break;; dnl /bin/sh is good enough
          a.*) dnl bash, ksh, and zsh all understand 'command', use that
               dnl to determine the absolute path of the shell
            lv_cv_wrapper_shell=`$lv_cv_wrapper_shell -c \
              "command -v $lv_cv_wrapper_shell"`
            case $lv_cv_wrapper_shell in
              /*) break;;
            esac
            ;;
        esac
      done
      rm -f conftest.a
    fi
  ])
  if test "x$lv_cv_wrapper_shell" != x/bin/sh; then
    lv_wrapper_shell=$lv_cv_wrapper_shell
  fi
  if test "x$lv_wrapper_shell" != x; then
    AC_DEFINE_UNQUOTED([VIR_WRAPPER_SHELL], ["$lv_wrapper_shell"],
      [Define to the absolute path of a shell that does not truncate on
       <> redirection, if /bin/sh does not fit the bill])
  fi
fi


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


dnl ==========================================================================
dnl find libxml2 library, borrowed from xmlsec
dnl ==========================================================================
LIBXML_CONFIG="xml2-config"
LIBXML_CFLAGS=""
LIBXML_LIBS=""
LIBXML_FOUND="no"

AC_ARG_WITH([libxml], [AS_HELP_STRING([--with-libxml=@<:@PFX@:>@],
   [libxml2 location])])
if test "x$with_libxml" = "xno" ; then
    AC_MSG_CHECKING(for libxml2 libraries >= $LIBXML_REQUIRED)
    AC_MSG_ERROR([libxml2 >= $LIBXML_REQUIRED is required for libvirt])
elif test "x$with_libxml" = "x" && test "x$PKG_CONFIG" != "x" ; then
    PKG_CHECK_MODULES(LIBXML, libxml-2.0 >= $LIBXML_REQUIRED, [LIBXML_FOUND=yes], [LIBXML_FOUND=no])
fi
if test "$LIBXML_FOUND" = "no" ; then
    if test "x$with_libxml" != "x" ; then
	LIBXML_CONFIG=$with_libxml/bin/$LIBXML_CONFIG
    fi
    AC_MSG_CHECKING(libxml2 $LIBXML_CONFIG >= $LIBXML_REQUIRED )
    if ! $LIBXML_CONFIG --version > /dev/null 2>&1 ; then
	AC_MSG_ERROR([Could not find libxml2 anywhere (see config.log for details).])
    fi
    vers=`$LIBXML_CONFIG --version | awk -F. '{ printf "%d", ($1 * 1000 + $2) * 1000 + $3;}'`
    minvers=`echo $LIBXML_REQUIRED | awk -F. '{ printf "%d", ($1 * 1000 + $2) * 1000 + $3;}'`
    if test "$vers" -ge "$minvers" ; then
        LIBXML_LIBS="`$LIBXML_CONFIG --libs`"
        LIBXML_CFLAGS="`$LIBXML_CONFIG --cflags`"
	LIBXML_FOUND="yes"
        AC_MSG_RESULT(yes)
    else
        AC_MSG_ERROR(
          [You need at least libxml2 $LIBXML_REQUIRED for this version of libvirt])
    fi
fi

AC_SUBST([LIBXML_CFLAGS])
AC_SUBST([LIBXML_LIBS])

dnl xmlURI structure has query_raw?
old_cflags="$CFLAGS"
old_libs="$LIBS"
CFLAGS="$CFLAGS $LIBXML_CFLAGS"
LIBS="$LIBS $LIBXML_LIBS"
AC_CHECK_MEMBER([struct _xmlURI.query_raw],
		[AC_DEFINE([HAVE_XMLURI_QUERY_RAW], [], [Have query_raw field in libxml2 xmlURI structure])],,
		[#include <libxml/uri.h>])
CFLAGS="$old_cflags"
LIBS="$old_libs"

dnl GnuTLS library
AC_ARG_WITH([gnutls],
  [AS_HELP_STRING([--with-gnutls],
    [use GNUTLS for encryption @<:@default=check@:>@])],
  [],
  [with_gnutls=check])


if test "x$with_gnutls" != "xno"; then
  if test "x$with_gnutls" != "xyes" && test "x$with_gnutls" != "xcheck"; then
    GNUTLS_CFLAGS="-I$with_gnutls/include"
    GNUTLS_LIBS="-L$with_gnutls/lib"
  fi
  fail=0
  old_cflags="$CFLAGS"
  old_libs="$LIBS"
  CFLAGS="$CFLAGS $GNUTLS_CFLAGS"
  LIBS="$LIBS $GNUTLS_LIBS"

  GNUTLS_FOUND=no
  GNUTLS_GCRYPT=unknown
  if test -x "$PKG_CONFIG" ; then
    dnl Triple probe: gnutls < 2.12 only used gcrypt, gnutls >= 3.0 uses
    dnl only nettle, and versions in between had a configure option.
    dnl Our goal is to avoid gcrypt if we can prove gnutls uses nettle,
    dnl but it is a safe fallback to use gcrypt if we can't prove anything.
    if $PKG_CONFIG --exists 'gnutls >= 3.0'; then
      GNUTLS_GCRYPT=no
    elif $PKG_CONFIG --exists 'gnutls >= 2.12'; then
      GNUTLS_GCRYPT=probe
    else
      GNUTLS_GCRYPT=yes
    fi
    PKG_CHECK_MODULES(GNUTLS, gnutls >= $GNUTLS_REQUIRED,
      [GNUTLS_FOUND=yes], [GNUTLS_FOUND=no])
  fi
  if test "$GNUTLS_FOUND" = "no"; then
    dnl pkg-config couldn't help us, assume gcrypt is necessary
    fail=0
    GNUTLS_GCRYPT=yes
    AC_CHECK_HEADER([gnutls/gnutls.h], [], [fail=1])
    AC_CHECK_LIB([gnutls], [gnutls_handshake],[], [fail=1], [-lgcrypt])

    test $fail = 0 && GNUTLS_FOUND=yes

    GNUTLS_LIBS="$GNUTLS_LIBS -lgnutls"
  fi
  if test "$GNUTLS_FOUND" = "no"; then
    if test "$with_gnutls" = "check"; then
      with_gnutls=no
      GNUTLS_LIBS=
      GNUTLS_CFLAGS=
    else
      AC_MSG_ERROR([You must install the GnuTLS library in order to compile and run libvirt])
    fi
  else
    dnl See comments above about when to use gcrypt.
    if test "$GNUTLS_GCRYPT" = probe; then
      case `$PKG_CONFIG --libs --static gnutls` in
        *gcrypt*) GNUTLS_GCRYPT=yes     ;;
        *nettle*) GNUTLS_GCRYPT=no      ;;
        *)        GNUTLS_GCRYPT=unknown ;;
      esac
    fi
    if test "$GNUTLS_GCRYPT" = yes || test "$GNUTLS_GCRYPT" = unknown; then
      GNUTLS_LIBS="$GNUTLS_LIBS -lgcrypt"
      dnl We're not using gcrypt deprecated features so define
      dnl GCRYPT_NO_DEPRECATED to avoid deprecated warnings
      GNUTLS_CFLAGS="$GNUTLS_CFLAGS -DGCRYPT_NO_DEPRECATED"
      AC_DEFINE_UNQUOTED([WITH_GNUTLS_GCRYPT], 1,
        [set to 1 if it is known or assumed that GNUTLS uses gcrypt])
    fi

    dnl gnutls 3.x moved some declarations to a new header
    AC_CHECK_HEADERS([gnutls/crypto.h], [], [], [[
      #include <gnutls/gnutls.h>
    ]])

    with_gnutls=yes
  fi

  LIBS="$old_libs"
  CFLAGS="$old_CFLAGS"
fi

if test "x$with_gnutls" = "xyes" ; then
  AC_DEFINE_UNQUOTED([WITH_GNUTLS], 1,
      [whether GNUTLS is available for encryption])
fi
AM_CONDITIONAL([WITH_GNUTLS], [test "x$with_gnutls" = "xyes"])
AC_SUBST([GNUTLS_CFLAGS])
AC_SUBST([GNUTLS_LIBS])


dnl PolicyKit library
POLKIT_CFLAGS=
POLKIT_LIBS=
PKCHECK_PATH=
AC_ARG_WITH([polkit],
  [AS_HELP_STRING([--with-polkit],
     [use PolicyKit for UNIX socket access checks @<:@default=check@:>@])],
  [],
  [with_polkit=check])

with_polkit0=no
with_polkit1=no
if test "x$with_polkit" = "xyes" || test "x$with_polkit" = "xcheck"; then
  dnl Check for new polkit first - just a binary
  AC_PATH_PROG([PKCHECK_PATH],[pkcheck], [], [/usr/sbin:$PATH])
  if test "x$PKCHECK_PATH" != "x" ; then
    AC_DEFINE_UNQUOTED([PKCHECK_PATH],["$PKCHECK_PATH"],[Location of pkcheck program])
    AC_MSG_CHECKING([whether pkcheck supports uid value])
    pkcheck_supports_uid=`$PKG_CONFIG --variable pkcheck_supports_uid polkit-gobject-1`
    if test "x$pkcheck_supports_uid" = "xtrue"; then
      AC_MSG_RESULT([yes])
      AC_DEFINE_UNQUOTED([PKCHECK_SUPPORTS_UID], 1, [Pass uid to pkcheck])
    else
      AC_MSG_RESULT([no])
    fi
    AC_DEFINE_UNQUOTED([WITH_POLKIT], 1,
        [use PolicyKit for UNIX socket access checks])
    AC_DEFINE_UNQUOTED([WITH_POLKIT1], 1,
        [use PolicyKit for UNIX socket access checks])
    with_polkit="yes"
    with_polkit1="yes"
  else
    dnl Check for old polkit second - library + binary
    PKG_CHECK_MODULES(POLKIT, polkit-dbus >= $POLKIT_REQUIRED,
      [with_polkit=yes], [
      if test "x$with_polkit" = "xcheck" ; then
         with_polkit=no
      else
         AC_MSG_ERROR(
           [You must install PolicyKit >= $POLKIT_REQUIRED to compile libvirt])
      fi
    ])
    if test "x$with_polkit" = "xyes" ; then
      AC_DEFINE_UNQUOTED([WITH_POLKIT], 1,
        [use PolicyKit for UNIX socket access checks])
      AC_DEFINE_UNQUOTED([WITH_POLKIT0], 1,
        [use PolicyKit for UNIX socket access checks])

      old_CFLAGS=$CFLAGS
      old_LIBS=$LIBS
      CFLAGS="$CFLAGS $POLKIT_CFLAGS"
      LIBS="$LIBS $POLKIT_LIBS"
      AC_CHECK_FUNCS([polkit_context_is_caller_authorized])
      CFLAGS="$old_CFLAGS"
      LIBS="$old_LIBS"

      AC_PATH_PROG([POLKIT_AUTH], [polkit-auth])
      if test "x$POLKIT_AUTH" != "x"; then
        AC_DEFINE_UNQUOTED([POLKIT_AUTH],["$POLKIT_AUTH"],[Location of polkit-auth program])
      fi
      with_polkit0="yes"
    fi
  fi
fi
AM_CONDITIONAL([WITH_POLKIT], [test "x$with_polkit" = "xyes"])
AM_CONDITIONAL([WITH_POLKIT0], [test "x$with_polkit0" = "xyes"])
AM_CONDITIONAL([WITH_POLKIT1], [test "x$with_polkit1" = "xyes"])
AC_SUBST([POLKIT_CFLAGS])
AC_SUBST([POLKIT_LIBS])

dnl firewalld
AC_ARG_WITH([firewalld],
  [AS_HELP_STRING([--with-firewalld],
    [enable firewalld support @<:@default=check@:>@])],
  [],
  [with_firewalld=check])
if test "x$with_firewalld" = "xcheck" ; then
   with_firewalld=$with_dbus
fi
if test "x$with_firewalld" == "xyes" ; then
  if test "x$with_dbus" != "xyes" ; then
     AC_MSG_ERROR([You must have dbus enabled for firewalld support])
  fi
  AC_DEFINE_UNQUOTED([HAVE_FIREWALLD], [1], [whether firewalld support is enabled])
fi
AM_CONDITIONAL([HAVE_FIREWALLD], [test "x$with_firewalld" != "xno"])


dnl UUCP style file locks for character devices
if test "$with_chrdev_lock_files" != "no"; then
  case $with_chrdev_lock_files in
  yes | auto)
    dnl Default locations for platforms, or disable if unknown
    if test "$with_linux" = "yes"; then
      with_chrdev_lock_files=/var/lock
    elif test "$with_chrdev_lock_files" = "auto"; then
      with_chrdev_lock_files=no
    fi ;;
  esac
  if test "$with_chrdev_lock_files" = "yes"; then
    AC_MSG_ERROR([You must specify path for the lock files on this
platform])
  fi
  AC_DEFINE_UNQUOTED([VIR_CHRDEV_LOCK_FILE_PATH], "$with_chrdev_lock_files",
                      [path to directory containing UUCP device lock files])
fi
AM_CONDITIONAL([VIR_CHRDEV_LOCK_FILE_PATH], [test "$with_chrdev_lock_files" != "no"])


AC_ARG_WITH([secdriver-selinux],
  [AS_HELP_STRING([--with-secdriver-selinux],
    [use SELinux security driver @<:@default=check@:>@])],
  [],
  [with_secdriver_selinux=check])

if test "$with_selinux" != "yes" ; then
  if test "$with_secdriver_selinux" = "check" ; then
    with_secdriver_selinux=no
  fi
  if test "$with_secdriver_selinux" != "no"; then
        AC_MSG_ERROR([You must install the libselinux development package and enable SELinux with the --with-selinux=yes in order to compile libvirt --with-secdriver-selinux=yes])
  fi
elif test "$with_secdriver_selinux" != "no"; then
  old_cflags="$CFLAGS"
  old_libs="$LIBS"
  CFLAGS="$CFLAGS $SELINUX_CFLAGS"
  LIBS="$CFLAGS $SELINUX_LIBS"

  fail=0
  AC_CHECK_FUNC([selinux_virtual_domain_context_path], [], [fail=1])
  AC_CHECK_FUNC([selinux_virtual_image_context_path], [], [fail=1])
  AC_CHECK_FUNCS([selinux_lxc_contexts_path])
  CFLAGS="$old_cflags"
  LIBS="$old_libs"

  if test "$fail" = "1" ; then
    if test "$with_secdriver_selinux" = "check" ; then
      with_secdriver_selinux=no
    else
      AC_MSG_ERROR([You must install libselinux development package >= 2.0.82 in order to compile libvirt --with-secdriver-selinux=yes])
    fi
  else
    with_secdriver_selinux=yes
    AC_DEFINE_UNQUOTED([WITH_SECDRIVER_SELINUX], 1, [whether SELinux security driver is available])
  fi
fi
AM_CONDITIONAL([WITH_SECDRIVER_SELINUX], [test "$with_secdriver_selinux" != "no"])


AC_ARG_WITH([secdriver-apparmor],
  [AS_HELP_STRING([--with-secdriver-apparmor],
    [use AppArmor security driver @<:@default=check@:>@])],
  [],
  [with_secdriver_apparmor=check])

if test "$with_apparmor" != "yes" ; then
  if test "$with_secdriver_apparmor" = "check" ; then
    with_secdriver_apparmor=no
  fi
  if test "$with_secdriver_apparmor" != "no" ; then
    AC_MSG_ERROR([You must install the AppArmor development package in order to compile libvirt])
  fi
elif test "with_secdriver_apparmor" != "no" ; then
  with_secdriver_apparmor=yes
  AC_DEFINE_UNQUOTED([WITH_SECDRIVER_APPARMOR], 1, [whether AppArmor security driver is available])
fi
AM_CONDITIONAL([WITH_SECDRIVER_APPARMOR], [test "$with_secdriver_apparmor" != "no"])


dnl DTrace static probes
AC_ARG_WITH([dtrace],
  [AS_HELP_STRING([--with-dtrace],
    [use dtrace for static probing @<:@default=check@:>@])],
  [],
  [with_dtrace=check])

if test "$with_dtrace" != "no" ; then
  AC_PATH_PROG([DTRACE], [dtrace], [], [/bin:/usr/bin])
  if test -z "$DTRACE" ; then
    if test "$with_dtrace" = "check"; then
      with_dtrace=no
    else
      AC_MSG_ERROR([You must install the 'dtrace' binary to enable libvirt static probes])
    fi
  else
    with_dtrace=yes
  fi
  if test "$with_dtrace" = "yes"; then
    AC_DEFINE_UNQUOTED([WITH_DTRACE_PROBES], 1, [whether DTrace static probes are available])
  fi
fi
AM_CONDITIONAL([WITH_DTRACE_PROBES], [test "$with_dtrace" != "no"])


dnl numad
AC_ARG_WITH([numad],
  [AS_HELP_STRING([--with-numad],
    [use numad to manage CPU placement dynamically @<:@default=check@:>@])],
  [],
  [with_numad=check])

if test "$with_numad" != "no" ; then
  fail=0

  AC_PATH_PROG([NUMAD], [numad], [], [/bin:/usr/bin:/usr/sbin])

  if test "$with_numad" = "check"; then
    test "$with_numactl" = "yes" || fail=1
    if test -z "$NUMAD" || test $fail = 1; then
      with_numad="no"
    else
      with_numad="yes"
    fi
  else
    test -z  "$NUMAD" &&
      AC_MSG_ERROR([You must install numad package to manage CPU and memory placement dynamically])

    test "$with_numactl" = "yes" || fail=1
    test $fail = 1 &&
      AC_MSG_ERROR([You must install the numactl development package in order to compile and run libvirt])
  fi
fi
if test "$with_numad" = "yes"; then
  AC_DEFINE_UNQUOTED([HAVE_NUMAD], 1, [whether numad is available])
  AC_DEFINE_UNQUOTED([NUMAD],["$NUMAD"], [Location or name of the numad program])
fi
AM_CONDITIONAL([HAVE_NUMAD], [test "$with_numad" != "no"])

dnl pcap lib
LIBPCAP_CONFIG="pcap-config"
LIBPCAP_CFLAGS=""
LIBPCAP_LIBS=""
LIBPCAP_FOUND="no"

AC_ARG_WITH([libpcap], [AS_HELP_STRING([--with-libpcap=@<:@PFX@:>@],
  [libpcap location])])
if test "$with_qemu" = "yes"; then
  case $with_libpcap in
    no)     LIBPCAP_CONFIG= ;;
    ''|yes) LIBPCAP_CONFIG="pcap-config" ;;
    *)      LIBPCAP_CONFIG="$with_libpcap/bin/pcap-config" ;;
  esac
  AS_IF([test "x$LIBPCAP_CONFIG" != "x"], [
    AC_MSG_CHECKING(libpcap $LIBPCAP_CONFIG >= $LIBPCAP_REQUIRED )
    if ! $LIBPCAP_CONFIG --libs > /dev/null 2>&1 ; then
      AC_MSG_RESULT(no)
    else
      LIBPCAP_LIBS="`$LIBPCAP_CONFIG --libs`"
      LIBPCAP_CFLAGS="`$LIBPCAP_CONFIG --cflags`"
      LIBPCAP_FOUND="yes"
      AC_MSG_RESULT(yes)
    fi
  ])
fi

if test "x$LIBPCAP_FOUND" = "xyes"; then
  AC_DEFINE_UNQUOTED([HAVE_LIBPCAP], 1, [whether libpcap can be used])
fi

AC_SUBST([LIBPCAP_CFLAGS])
AC_SUBST([LIBPCAP_LIBS])



dnl
dnl Checks for the UML driver
dnl

if test "$with_libvirtd" = "no" ; then
  with_uml=no
fi
if test "$with_uml" = "yes" || test "$with_uml" = "check"; then
    AC_CHECK_HEADER([sys/inotify.h], [
        with_uml=yes
    ], [
        if test "$with_uml" = "check"; then
            with_uml=no
            AC_MSG_NOTICE([<sys/inotify.h> is required for the UML driver, disabling it])
        else
            AC_MSG_ERROR([The <sys/inotify.h> is required for the UML driver. Upgrade your libc6.])
        fi
    ])
fi
if test "$with_uml" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_UML], 1, [whether UML driver is enabled])
fi
AM_CONDITIONAL([WITH_UML], [test "$with_uml" = "yes"])



dnl
dnl check for PHYP
dnl

if test "$with_phyp" != "no"; then
  if test "$with_ssh2" = "no" ; then
    if test "$with_phyp" = "check"; then
      with_phyp=no
    else
      AC_MSG_ERROR([libssh2 is required for Phyp driver])
    fi
  else
    with_phyp=yes
  fi
fi

if test "$with_phyp" = "yes"; then
    AC_DEFINE_UNQUOTED([WITH_PHYP], 1, [whether IBM HMC / IVM driver is enabled])
fi

AM_CONDITIONAL([WITH_PHYP],[test "$with_phyp" = "yes"])

dnl virsh libraries
VIRSH_LIBS="$VIRSH_LIBS $READLINE_LIBS"
AC_SUBST([VIRSH_LIBS])

dnl check if the network driver should be compiled

AC_ARG_WITH([network],
  [AS_HELP_STRING([--with-network],
    [with virtual network driver @<:@default=yes@:>@])],
  [],[with_network=yes])

dnl there's no use compiling the network driver without the libvirt
dnl daemon, nor compiling it for MacOS X, where it breaks the compile

if test "$with_libvirtd" = "no" || test "$with_osx" = "yes"; then
  with_network=no
fi

if test "$with_network" = "yes" ; then
  AC_DEFINE_UNQUOTED([WITH_NETWORK], 1, [whether network driver is enabled])
fi
AM_CONDITIONAL([WITH_NETWORK], [test "$with_network" = "yes"])

with_bridge=no
if test "$with_qemu:$with_lxc:$with_network" != "no:no:no"; then
    with_bridge=yes
    AC_DEFINE_UNQUOTED([WITH_BRIDGE], 1, [whether bridge code is needed])
fi
AM_CONDITIONAL([WITH_BRIDGE], [test "$with_bridge" = "yes"])


AC_ARG_WITH([secrets],
  [AS_HELP_STRING([--with-secrets],
    [with local secrets management driver @<:@default=yes@:>@])],
  [],[with_secrets=yes])

if test "$with_libvirtd" = "no"; then
  with_secrets=no
fi
if test "$with_secrets" = "yes" ; then
  AC_DEFINE_UNQUOTED([WITH_SECRETS], 1, [whether local secrets management driver is available])
fi
AM_CONDITIONAL([WITH_SECRETS], [test "$with_secrets" = "yes"])


AC_ARG_WITH([storage-dir],
  [AS_HELP_STRING([--with-storage-dir],
    [with directory backend for the storage driver @<:@default=yes@:>@])],
  [],[with_storage_dir=yes])
AC_ARG_WITH([storage-fs],
  [AS_HELP_STRING([--with-storage-fs],
    [with FileSystem backend for the storage driver @<:@default=check@:>@])],
  [],[with_storage_fs=check])
AC_ARG_WITH([storage-lvm],
  [AS_HELP_STRING([--with-storage-lvm],
    [with LVM backend for the storage driver @<:@default=check@:>@])],
  [],[with_storage_lvm=check])
AC_ARG_WITH([storage-iscsi],
  [AS_HELP_STRING([--with-storage-iscsi],
    [with iSCSI backend for the storage driver @<:@default=check@:>@])],
  [],[with_storage_iscsi=check])
AC_ARG_WITH([storage-scsi],
  [AS_HELP_STRING([--with-storage-scsi],
    [with SCSI backend for the storage driver @<:@default=check@:>@])],
  [],[with_storage_scsi=check])
AC_ARG_WITH([storage-mpath],
  [AS_HELP_STRING([--with-storage-mpath],
    [with mpath backend for the storage driver @<:@default=check@:>@])],
  [],[with_storage_mpath=check])
AC_ARG_WITH([storage-disk],
  [AS_HELP_STRING([--with-storage-disk],
    [with GPartd Disk backend for the storage driver @<:@default=check@:>@])],
  [],[with_storage_disk=check])
AC_ARG_WITH([storage-rbd],
  [AS_HELP_STRING([--with-storage-rbd],
    [with RADOS Block Device backend for the storage driver
     @<:@default=check@:>@])],
  [],[with_storage_rbd=check])
AC_ARG_WITH([storage-sheepdog],
  [AS_HELP_STRING([--with-storage-sheepdog],
    [with Sheepdog backend for the storage driver @<:@default=check@:>@])],
  [],[with_storage_sheepdog=check])
AC_ARG_WITH([storage-gluster],
  [AS_HELP_STRING([--with-storage-gluster],
    [with Gluster backend for the storage driver @<:@default=check@:>@])],
  [],[with_storage_gluster=check])

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
fi
if test "$with_storage_dir" = "yes" ; then
  AC_DEFINE_UNQUOTED([WITH_STORAGE_DIR], 1, [whether directory backend for storage driver is enabled])
fi
AM_CONDITIONAL([WITH_STORAGE_DIR], [test "$with_storage_dir" = "yes"])

dnl storage-fs does not work on MacOS X

if test "$with_osx" = "yes"; then
  with_storage_fs=no
fi

if test "$with_storage_fs" = "yes" || test "$with_storage_fs" = "check"; then
    AC_CHECK_HEADER([mntent.h],,
    [
        if test "$with_storage_fs" = "check"; then
            with_storage_fs=no
            AC_MSG_NOTICE([<mntent.h> is required for the FS storage driver, disabling it])
        else
            AC_MSG_ERROR([<mntent.h> is required for the FS storage driver])
        fi
    ])
fi

if test "$with_storage_fs" = "yes" || test "$with_storage_fs" = "check"; then
  AC_PATH_PROG([MOUNT], [mount], [], [$PATH:/sbin:/usr/sbin])
  AC_PATH_PROG([UMOUNT], [umount], [], [$PATH:/sbin:/usr/sbin])
  AC_PATH_PROG([MKFS], [mkfs], [], [$PATH:/sbin:/usr/sbin])
  if test "$with_storage_fs" = "yes" ; then
    if test -z "$MOUNT" ; then AC_MSG_ERROR([We need mount for FS storage driver]) ; fi
    if test -z "$UMOUNT" ; then AC_MSG_ERROR([We need umount for FS storage driver]) ; fi
    if test -z "$MKFS" ; then AC_MSG_ERROR([We need mkfs for FS storage driver]) ; fi
  else
    if test -z "$MOUNT" ; then with_storage_fs=no ; fi
    if test -z "$UMOUNT" ; then with_storage_fs=no ; fi
    if test -z "$MKFS" ; then with_storage_fs=no ; fi

    if test "$with_storage_fs" = "check" ; then with_storage_fs=yes ; fi
  fi

  if test "$with_storage_fs" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_STORAGE_FS], 1, [whether FS backend for storage driver is enabled])
    AC_DEFINE_UNQUOTED([MOUNT],["$MOUNT"],
        [Location or name of the mount program])
    AC_DEFINE_UNQUOTED([UMOUNT],["$UMOUNT"],
        [Location or name of the mount program])
    AC_DEFINE_UNQUOTED([MKFS],["$MKFS"],
        [Location or name of the mkfs program])
  fi
fi
AM_CONDITIONAL([WITH_STORAGE_FS], [test "$with_storage_fs" = "yes"])
if test "$with_storage_fs" = "yes"; then
  AC_PATH_PROG([SHOWMOUNT], [showmount], [], [$PATH:/sbin:/usr/sbin])
  AC_DEFINE_UNQUOTED([SHOWMOUNT], ["$SHOWMOUNT"],
    [Location or name of the showmount program])
fi

if test "$with_storage_lvm" = "yes" || test "$with_storage_lvm" = "check"; then
  AC_PATH_PROG([PVCREATE], [pvcreate], [], [$PATH:/sbin:/usr/sbin])
  AC_PATH_PROG([VGCREATE], [vgcreate], [], [$PATH:/sbin:/usr/sbin])
  AC_PATH_PROG([LVCREATE], [lvcreate], [], [$PATH:/sbin:/usr/sbin])
  AC_PATH_PROG([PVREMOVE], [pvremove], [], [$PATH:/sbin:/usr/sbin])
  AC_PATH_PROG([VGREMOVE], [vgremove], [], [$PATH:/sbin:/usr/sbin])
  AC_PATH_PROG([LVREMOVE], [lvremove], [], [$PATH:/sbin:/usr/sbin])
  AC_PATH_PROG([LVCHANGE], [lvchange], [], [$PATH:/sbin:/usr/sbin])
  AC_PATH_PROG([VGCHANGE], [vgchange], [], [$PATH:/sbin:/usr/sbin])
  AC_PATH_PROG([VGSCAN], [vgscan], [], [$PATH:/sbin:/usr/sbin])
  AC_PATH_PROG([PVS], [pvs], [], [$PATH:/sbin:/usr/sbin])
  AC_PATH_PROG([VGS], [vgs], [], [$PATH:/sbin:/usr/sbin])
  AC_PATH_PROG([LVS], [lvs], [], [$PATH:/sbin:/usr/sbin])

  if test "$with_storage_lvm" = "yes" ; then
    if test -z "$PVCREATE" ; then AC_MSG_ERROR([We need pvcreate for LVM storage driver]) ; fi
    if test -z "$VGCREATE" ; then AC_MSG_ERROR([We need vgcreate for LVM storage driver]) ; fi
    if test -z "$LVCREATE" ; then AC_MSG_ERROR([We need lvcreate for LVM storage driver]) ; fi
    if test -z "$PVREMOVE" ; then AC_MSG_ERROR([We need pvremove for LVM storage driver]) ; fi
    if test -z "$VGREMOVE" ; then AC_MSG_ERROR([We need vgremove for LVM storage driver]) ; fi
    if test -z "$LVREMOVE" ; then AC_MSG_ERROR([We need lvremove for LVM storage driver]) ; fi
    if test -z "$LVCHANGE" ; then AC_MSG_ERROR([We need lvchange for LVM storage driver]) ; fi
    if test -z "$VGCHANGE" ; then AC_MSG_ERROR([We need vgchange for LVM storage driver]) ; fi
    if test -z "$VGSCAN" ; then AC_MSG_ERROR([We need vgscan for LVM storage driver]) ; fi
    if test -z "$PVS" ; then AC_MSG_ERROR([We need pvs for LVM storage driver]) ; fi
    if test -z "$VGS" ; then AC_MSG_ERROR([We need vgs for LVM storage driver]) ; fi
    if test -z "$LVS" ; then AC_MSG_ERROR([We need lvs for LVM storage driver]) ; fi
  else
    if test -z "$PVCREATE" ; then with_storage_lvm=no ; fi
    if test -z "$VGCREATE" ; then with_storage_lvm=no ; fi
    if test -z "$LVCREATE" ; then with_storage_lvm=no ; fi
    if test -z "$PVREMOVE" ; then with_storage_lvm=no ; fi
    if test -z "$VGREMOVE" ; then with_storage_lvm=no ; fi
    if test -z "$LVREMOVE" ; then with_storage_lvm=no ; fi
    if test -z "$LVCHANGE" ; then with_storage_lvm=no ; fi
    if test -z "$VGCHANGE" ; then with_storage_lvm=no ; fi
    if test -z "$VGSCAN" ; then with_storage_lvm=no ; fi
    if test -z "$PVS" ; then with_storage_lvm=no ; fi
    if test -z "$VGS" ; then with_storage_lvm=no ; fi
    if test -z "$LVS" ; then with_storage_lvm=no ; fi

    if test "$with_storage_lvm" = "check" ; then with_storage_lvm=yes ; fi
  fi

  if test "$with_storage_lvm" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_STORAGE_LVM], 1, [whether LVM backend for storage driver is enabled])
    AC_DEFINE_UNQUOTED([PVCREATE],["$PVCREATE"],[Location of pvcreate program])
    AC_DEFINE_UNQUOTED([VGCREATE],["$VGCREATE"],[Location of vgcreate program])
    AC_DEFINE_UNQUOTED([LVCREATE],["$LVCREATE"],[Location of lvcreate program])
    AC_DEFINE_UNQUOTED([PVREMOVE],["$PVREMOVE"],[Location of pvremove program])
    AC_DEFINE_UNQUOTED([VGREMOVE],["$VGREMOVE"],[Location of vgremove program])
    AC_DEFINE_UNQUOTED([LVREMOVE],["$LVREMOVE"],[Location of lvremove program])
    AC_DEFINE_UNQUOTED([LVCHANGE],["$LVCHANGE"],[Location of lvchange program])
    AC_DEFINE_UNQUOTED([VGCHANGE],["$VGCHANGE"],[Location of vgchange program])
    AC_DEFINE_UNQUOTED([VGSCAN],["$VGSCAN"],[Location of vgscan program])
    AC_DEFINE_UNQUOTED([PVS],["$PVS"],[Location of pvs program])
    AC_DEFINE_UNQUOTED([VGS],["$VGS"],[Location of vgs program])
    AC_DEFINE_UNQUOTED([LVS],["$LVS"],[Location of lvs program])
  fi
fi
AM_CONDITIONAL([WITH_STORAGE_LVM], [test "$with_storage_lvm" = "yes"])



if test "$with_storage_iscsi" = "yes" || test "$with_storage_iscsi" = "check"; then
  AC_PATH_PROG([ISCSIADM], [iscsiadm], [], [$PATH:/sbin:/usr/sbin])
  if test "$with_storage_iscsi" = "yes" ; then
    if test -z "$ISCSIADM" ; then AC_MSG_ERROR([We need iscsiadm for iSCSI storage driver]) ; fi
  else
    if test -z "$ISCSIADM" ; then with_storage_iscsi=no ; fi

    if test "$with_storage_iscsi" = "check" ; then with_storage_iscsi=yes ; fi
  fi

  if test "$with_storage_iscsi" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_STORAGE_ISCSI], 1, [whether iSCSI backend for storage driver is enabled])
    AC_DEFINE_UNQUOTED([ISCSIADM],["$ISCSIADM"],[Location of iscsiadm program])
  fi
fi
AM_CONDITIONAL([WITH_STORAGE_ISCSI], [test "$with_storage_iscsi" = "yes"])

if test "$with_storage_scsi" = "check"; then
   with_storage_scsi=yes

   AC_DEFINE_UNQUOTED([WITH_STORAGE_SCSI], 1,
     [whether SCSI backend for storage driver is enabled])
fi
AM_CONDITIONAL([WITH_STORAGE_SCSI], [test "$with_storage_scsi" = "yes"])

if test "$with_storage_mpath" = "check"; then
   if test "$with_linux" = "yes"; then
      with_storage_mpath=yes

      AC_DEFINE_UNQUOTED([WITH_STORAGE_MPATH], 1,
        [whether mpath backend for storage driver is enabled])
   else
      with_storage_mpath=no
   fi
fi
AM_CONDITIONAL([WITH_STORAGE_MPATH], [test "$with_storage_mpath" = "yes"])

LIBRBD_LIBS=
if test "$with_storage_rbd" = "yes" || test "$with_storage_rbd" = "check"; then
    AC_CHECK_HEADER([rbd/librbd.h], [LIBRBD_FOUND=yes; break;])

    if test "$LIBRBD_FOUND" = "yes"; then
        with_storage_rbd=yes
        LIBRBD_LIBS="-lrbd -lrados"
        AC_DEFINE_UNQUOTED([WITH_STORAGE_RBD], [1],
         [whether RBD backend for storage driver is enabled])
    else
        with_storage_rbd=no
    fi
fi
AM_CONDITIONAL([WITH_STORAGE_RBD], [test "$with_storage_rbd" = "yes"])
AC_SUBST([LIBRBD_LIBS])

if test "$with_storage_sheepdog" = "yes" ||
   test "$with_storage_sheepdog" = "check"; then
  AC_PATH_PROG([COLLIE], [collie], [], [$PATH:/sbin:/usr/sbin])

  if test "$with_storage_sheepdog" = "yes"; then
    if test -z "$COLLIE"; then
      AC_MSG_ERROR([We need collie for Sheepdog storage driver])
    fi
  else
    if test -z "$COLLIE"; then
      with_storage_sheepdog=no
    fi

    if test "$with_storage_sheepdog" = "check"; then
      with_storage_sheepdog=yes
    fi
  fi

  if test "$with_storage_sheepdog" = "yes"; then
    AC_DEFINE_UNQUOTED([WITH_STORAGE_SHEEPDOG], 1,
      [whether Sheepdog backend for storage driver is enabled])
    AC_DEFINE_UNQUOTED([COLLIE],["$COLLIE"],[Location of collie program])
  fi
fi
AM_CONDITIONAL([WITH_STORAGE_SHEEPDOG],
  [test "$with_storage_sheepdog" = "yes"])

LIBGLUSTER_LIBS=
if test "$with_storage_gluster" = "check"; then
  with_storage_gluster=$with_glusterfs
fi
if test "$with_storage_gluster" = "yes"; then
  if test "$with_glusterfs" = no; then
    AC_MSG_ERROR([Need glusterfs (libgfapi) for gluster storage driver])
  fi
  AC_DEFINE_UNQUOTED([WITH_STORAGE_GLUSTER], [1],
    [whether Gluster backend for storage driver is enabled])
fi
AM_CONDITIONAL([WITH_STORAGE_GLUSTER], [test "$with_storage_gluster" = "yes"])


LIBPARTED_CFLAGS=
LIBPARTED_LIBS=
if test "$with_storage_disk" = "yes" ||
   test "$with_storage_disk" = "check"; then
  AC_PATH_PROG([PARTED], [parted], [], [$PATH:/sbin:/usr/sbin])
  AC_PATH_PROG([DMSETUP], [dmsetup], [], [$PATH:/sbin:/usr/sbin])
  if test -z "$PARTED" ; then
    PARTED_FOUND=no
  else
    PARTED_FOUND=yes
  fi

  if test -z "$DMSETUP" ; then
    DMSETUP_FOUND=no
  else
    DMSETUP_FOUND=yes
  fi

  if test "$PARTED_FOUND" = "yes" && test "x$PKG_CONFIG" != "x" ; then
    PKG_CHECK_MODULES([LIBPARTED], [libparted >= $PARTED_REQUIRED], [],
      [PARTED_FOUND=no])
  fi
  if test "$PARTED_FOUND" = "no"; then
    # RHEL-5 vintage parted is missing pkg-config files
    save_LIBS="$LIBS"
    save_CFLAGS="$CFLAGS"
    PARTED_FOUND=yes
    AC_CHECK_HEADER([parted/parted.h],,[PARTED_FOUND=no])
    AC_CHECK_LIB([uuid], [uuid_generate],,[PARTED_FOUND=no])
    AC_CHECK_LIB([parted], [ped_device_read],,[PARTED_FOUND=no])
    LIBPARTED_LIBS="-luuid -lparted"
    LIBS="$save_LIBS"
    CFLAGS="$save_CFLAGS"
  fi

  if test "$with_storage_disk" = "yes" &&
     test "$PARTED_FOUND:$DMSETUP_FOUND" != "yes:yes"; then
    AC_MSG_ERROR([Need both parted and dmsetup for disk storage driver])
  fi

  if test "$with_storage_disk" = "check"; then
    if test "$PARTED_FOUND:$DMSETUP_FOUND" != "yes:yes"; then
      with_storage_disk=no
    else
      with_storage_disk=yes
    fi
  fi

  if test "$with_storage_disk" = "yes"; then
    AC_DEFINE_UNQUOTED([WITH_STORAGE_DISK], 1,
      [whether Disk backend for storage driver is enabled])
    AC_DEFINE_UNQUOTED([PARTED],["$PARTED"],
      [Location or name of the parted program])
    AC_DEFINE_UNQUOTED([DMSETUP],["$DMSETUP"],
      [Location or name of the dmsetup program])
  fi
fi
AM_CONDITIONAL([WITH_STORAGE_DISK], [test "$with_storage_disk" = "yes"])
AC_SUBST([LIBPARTED_CFLAGS])
AC_SUBST([LIBPARTED_LIBS])

if test "$with_storage_mpath" = "yes" ||
   test "$with_storage_disk" = "yes"; then
   DEVMAPPER_CFLAGS=
   DEVMAPPER_LIBS=
   PKG_CHECK_MODULES([DEVMAPPER], [devmapper >= $DEVMAPPER_REQUIRED], [], [DEVMAPPER_FOUND=no])
   if test "$DEVMAPPER_FOUND" = "no"; then
     # devmapper is missing pkg-config files in ubuntu, suse, etc
     save_LIBS="$LIBS"
     save_CFLAGS="$CFLAGS"
     DEVMAPPER_FOUND=yes
     AC_CHECK_LIB([devmapper], [dm_task_run],,[DEVMAPPER_FOUND=no])
     DEVMAPPER_LIBS="-ldevmapper"
     LIBS="$save_LIBS"
     CFLAGS="$save_CFLAGS"
   fi
   AC_CHECK_HEADERS([libdevmapper.h],,[DEVMAPPER_FOUND=no])
   if test "$DEVMAPPER_FOUND" = "no" ; then
     AC_MSG_ERROR([You must install device-mapper-devel/libdevmapper >= $DEVMAPPER_REQUIRED to compile libvirt])
   fi

fi
AC_SUBST([DEVMAPPER_CFLAGS])
AC_SUBST([DEVMAPPER_LIBS])

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
dnl check for (ESX)
dnl

if test "$with_curl" != "yes" ; then
  if test "$with_esx" != "yes"; then
    with_esx=no
  else
    AC_MSG_ERROR([Curl is required for the ESX driver])
  fi
else
  if test "$with_esx" = "check"; then
    with_esx=yes
  fi
fi

if test "$with_esx" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_ESX], 1, [whether ESX driver is enabled])
fi
AM_CONDITIONAL([WITH_ESX], [test "$with_esx" = "yes"])

with_vmx=yes
if test "$with_esx" != "yes" && test "$with_vmware" != "yes"; then
  with_vmx=no
fi
if test "$with_vmx" = "yes" ; then
  AC_DEFINE_UNQUOTED([WITH_VMX], 1, [whether VMware VMX config handling is enabled])
fi
AM_CONDITIONAL([WITH_VMX], [test "$with_vmx" = "yes"])

if test "$with_xenapi" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_XENAPI], 1, [whether XenAPI driver is enabled])
fi
AM_CONDITIONAL([WITH_XENAPI], [test "$with_xenapi" = "yes"])


dnl
dnl check for Hyper-V
dnl

if test "$with_hyperv" != "no"; then
  if test "$with_openwsman" != "yes"; then
    if test "$with_hyperv" = "check"; then
      with_hyperv=no
    else
      AC_MSG_ERROR([openwsman is required for the Hyper-V driver])
    fi
  else
    with_hyperv=yes
  fi
fi

if test "$with_hyperv" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_HYPERV], 1, [whether Hyper-V driver is enabled])
fi
AM_CONDITIONAL([WITH_HYPERV], [test "$with_hyperv" = "yes"])


dnl Allow perl/python overrides
AC_PATH_PROG([PYTHON], [python])
AC_PATH_PROG([PERL], [perl])

AC_ARG_ENABLE([with-test-suite],
              [AS_HELP_STRING([--with-test-suite],
                 [build test suite by default @<:@default=check@:>@])],
              [case "${withval}" in
                 yes|no|check) ;;
                 *)      AC_MSG_ERROR([bad value ${withval} for tests option]) ;;
              esac],
              [withval=check])

AC_MSG_CHECKING([Whether to build test suite by default])
if test "$withval" = "check" ; then
  if test -d $srcdir/.git ; then
    withval=yes
  else
    withval=no
  fi
fi
AC_MSG_RESULT([$withval])
AM_CONDITIONAL([WITH_TESTS], [test "$withval" = "yes"])

AC_ARG_ENABLE([expensive-tests],
  [AS_HELP_STRING([--enable-expensive-tests],
    [set the default for enabling expensive tests (gnulib and long timeouts) ]
    [@<:@default=check@:>@; use VIR_TEST_EXPENSIVE to override during make])],
  [case $enableval in
    0|no) VIR_TEST_EXPENSIVE_DEFAULT=0 ;;
    1|yes) VIR_TEST_EXPENSIVE_DEFAULT=1 ;;
    check) ;;
    *) AC_MSG_ERROR([bad value ${enableval} for enable-expensive-tests option])
      ;;
  esac], [enableval=check])
if test "$enableval" = check; then
  if test -d $srcdir/.git ; then
    VIR_TEST_EXPENSIVE_DEFAULT=0
  else
    VIR_TEST_EXPENSIVE_DEFAULT=1
  fi
fi
AC_SUBST([VIR_TEST_EXPENSIVE_DEFAULT])
AM_CONDITIONAL([WITH_EXPENSIVE_TESTS], [test $VIR_TEST_EXPENSIVE_DEFAULT = 1])

AC_ARG_ENABLE([test-coverage],
  [AS_HELP_STRING([--enable-test-coverage],
    [turn on code coverage instrumentation @<:@default=no@:>@])],
[case "${enableval}" in
   yes|no) ;;
   *)      AC_MSG_ERROR([bad value ${enableval} for test-coverage option]) ;;
 esac],
              [enableval=no])
enable_coverage=$enableval

if test "${enable_coverage}" = yes; then
  save_WARN_CFLAGS=$WARN_CFLAGS
  WARN_CFLAGS=
  gl_WARN_ADD([-fprofile-arcs])
  gl_WARN_ADD([-ftest-coverage])
  COVERAGE_FLAGS=$WARN_CFLAGS
  AC_SUBST([COVERAGE_CFLAGS], [$COVERAGE_FLAGS])
  AC_SUBST([COVERAGE_LDFLAGS], [$COVERAGE_FLAGS])
  WARN_CFLAGS=$save_WARN_CFLAGS
fi

AC_ARG_ENABLE([test-oom],
  [AS_HELP_STRING([--enable-test-oom],
    [memory allocation failure checking @<:@default=no@:>@])],
[case "${enableval}" in
   yes|no) ;;
   *)      AC_MSG_ERROR([bad value ${enableval} for test-oom option]) ;;
 esac],
              [enableval=no])
enable_oom=$enableval

if test "${enable_oom}" = yes; then
  have_trace=yes
  AC_CHECK_HEADER([execinfo.h],[],[have_trace=no])
  AC_CHECK_FUNC([backtrace],[],[have_trace=no])
  if test "$have_trace" = "yes"; then
    AC_DEFINE([TEST_OOM_TRACE], 1, [Whether backtrace() is available])
  fi
  AC_DEFINE([TEST_OOM], 1, [Whether malloc OOM checking is enabled])
fi


AC_ARG_ENABLE([test-locking],
  [AS_HELP_STRING([--enable-test-locking],
    [thread locking tests using CIL @<:@default=no@:>@])],
[case "${enableval}" in
   yes|no) ;;
   *)      AC_MSG_ERROR([bad value ${enableval} for test-locking option]) ;;
 esac],
              [enableval=no])
enable_locking=$enableval

if test "$enable_locking" = "yes"; then
  LOCK_CHECKING_CFLAGS="-Dbool=char -D_Bool=char -save-temps"
  AC_SUBST([LOCK_CHECKING_CFLAGS])
fi
AM_CONDITIONAL([WITH_CIL],[test "$enable_locking" = "yes"])

dnl Enable building libvirtd?
AM_CONDITIONAL([WITH_LIBVIRTD],[test "x$with_libvirtd" = "xyes"])

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

dnl Extra link-time flags for Cygwin.
dnl Copied from libxml2 configure.in, but I removed mingw changes
dnl for now since I'm not supporting mingw at present.  - RWMJ
CYGWIN_EXTRA_LDFLAGS=
CYGWIN_EXTRA_LIBADD=
MINGW_EXTRA_LDFLAGS=
WIN32_EXTRA_CFLAGS=
dnl libvirt.syms is generated in builddir, but libvirt_qemu.syms is in git;
dnl hence the asymmetric naming of these two symbol files.
LIBVIRT_SYMBOL_FILE=libvirt.syms
LIBVIRT_LXC_SYMBOL_FILE='$(srcdir)/libvirt_lxc.syms'
LIBVIRT_QEMU_SYMBOL_FILE='$(srcdir)/libvirt_qemu.syms'
MSCOM_LIBS=
case "$host" in
  *-*-cygwin*)
    CYGWIN_EXTRA_LDFLAGS="-no-undefined"
    CYGWIN_EXTRA_LIBADD="${INTLLIBS}"
    MSCOM_LIBS="-lole32 -loleaut32"
    ;;
  *-*-mingw*)
    MINGW_EXTRA_LDFLAGS="-no-undefined"
    MSCOM_LIBS="-lole32 -loleaut32"
    ;;
  *-*-msvc*)
    MSCOM_LIBS="-lole32 -loleaut32"
    ;;
esac
case "$host" in
  *-*-mingw* | *-*-cygwin* | *-*-msvc* )
    # If the host is Windows, and shared libraries are disabled, we
    # need to add -DLIBVIRT_STATIC to the CFLAGS for proper linking
    if test "x$enable_shared" = "xno"; then
      WIN32_EXTRA_CFLAGS="-DLIBVIRT_STATIC"
    fi
esac
case "$host" in
  *-*-mingw* | *-*-msvc* )
    # Also set the symbol file to .def, so src/Makefile generates libvirt.def
    # from libvirt.syms and passes libvirt.def instead of libvirt.syms to the linker
    LIBVIRT_SYMBOL_FILE=libvirt.def
    LIBVIRT_LXC_SYMBOL_FILE=libvirt_lxc.def
    LIBVIRT_QEMU_SYMBOL_FILE=libvirt_qemu.def
    # mingw's ld has the --version-script parameter, but it requires a .def file
    # instead to work properly, therefore clear --version-script here and use
    # -Wl, to pass the .def file to the linker
    # cygwin's ld has the --version-script parameter too, but for some reason
    # it's working there as expected
    VERSION_SCRIPT_FLAGS="-Wl,"
    ;;
esac
AC_SUBST([CYGWIN_EXTRA_LDFLAGS])
AC_SUBST([CYGWIN_EXTRA_LIBADD])
AC_SUBST([MINGW_EXTRA_LDFLAGS])
AC_SUBST([WIN32_EXTRA_CFLAGS])
AC_SUBST([LIBVIRT_SYMBOL_FILE])
AC_SUBST([LIBVIRT_LXC_SYMBOL_FILE])
AC_SUBST([LIBVIRT_QEMU_SYMBOL_FILE])
AC_SUBST([VERSION_SCRIPT_FLAGS])
AC_SUBST([MSCOM_LIBS])


dnl Look for windres to build a Windows icon resource.
case "$host" in
  *-*-mingw* | *-*-cygwin* | *-*-msvc* )
    AC_CHECK_TOOL([WINDRES], [windres], [])
    ;;
esac
AM_CONDITIONAL([WITH_WIN_ICON], [test "$WINDRES" != ""])


dnl Driver-Modules library
AC_ARG_WITH([driver-modules],
  [AS_HELP_STRING([--with-driver-modules],
    [build drivers as loadable modules @<:@default=check@:>@])],
  [],
  [with_driver_modules=check])

if test "$with_libvirtd" = "no" ; then
  with_driver_modules=no
fi

DRIVER_MODULE_CFLAGS=
DRIVER_MODULE_LIBS=
if test "$with_driver_modules" = "yes" || test "$with_driver_modules" = "check"; then
  if test "$dlfcn_found" != "yes" || test "$dlopen_found" != "yes"; then
    if test "$with_driver_modules" = "yes" ; then
      AC_MSG_ERROR([You must have dlfcn.h / dlopen() support to build driver modules])
    else
      with_driver_modules=no
    fi
  else
    with_driver_modules=yes
  fi
fi

if test "$with_driver_modules" = "yes" ; then
  DRIVER_MODULE_LDFLAGS="-export-dynamic"
  case $ac_cv_search_dlopen in
    no*) DRIVER_MODULE_LIBS= ;;
    *) DRIVER_MODULE_LIBS=$ac_cv_search_dlopen ;;
  esac
  AC_DEFINE_UNQUOTED([WITH_DRIVER_MODULES], 1, [whether to build drivers as modules])
fi
AM_CONDITIONAL([WITH_DRIVER_MODULES], [test "$with_driver_modules" != "no"])
AC_SUBST([DRIVER_MODULE_LDFLAGS])
AC_SUBST([DRIVER_MODULE_LIBS])


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

dnl nwfilter should only be compiled for linux, and only if the
dnl libvirt daemon is also being compiled

with_nwfilter=yes
if test "$with_libvirtd" = "no" || test "$with_linux" != "yes"; then
  with_nwfilter=no
fi
if test "$with_nwfilter" = "yes" ; then
  AC_DEFINE([WITH_NWFILTER], 1, [whether local network filter management driver is available])
fi
AM_CONDITIONAL([WITH_NWFILTER], [test "$with_nwfilter" = "yes"])

dnl check if the interface driver should be compiled
AC_ARG_WITH([interface],
  [AS_HELP_STRING([--with-interface],
    [with host interface driver @<:@default=check@:>@])],
  [],[with_interface=check])

dnl Don't compile the interface driver without libvirtd
if test "$with_libvirtd" = "no" ; then
  with_interface=no
fi

dnl The interface driver depends on the netcf library or udev library
case $with_interface:$with_netcf:$with_udev in
    check:*yes*) with_interface=yes ;;
    check:no:no) with_interface=no ;;
    yes:no:no) AC_MSG_ERROR([Requested the Interface driver without netcf or udev support]) ;;
esac

if test "$with_interface" = "yes" ; then
  AC_DEFINE_UNQUOTED([WITH_INTERFACE], [1],
    [whether the interface driver is enabled])
fi
AM_CONDITIONAL([WITH_INTERFACE], [test "$with_interface" = "yes"])


if test $with_freebsd = yes || test $with_osx = yes; then
  default_qemu_user=root
  default_qemu_group=wheel
else
  default_qemu_user=root
  default_qemu_group=root
fi

AC_ARG_WITH([qemu-user],
  [AS_HELP_STRING([--with-qemu-user],
    [username to run QEMU system instance as
     @<:@default=platform dependent@:>@])],
  [QEMU_USER=${withval}],
  [QEMU_USER=${default_qemu_user}])
AC_ARG_WITH([qemu-group],
  [AS_HELP_STRING([--with-qemu-group],
    [groupname to run QEMU system instance as
     @<:@default=platform dependent@:>@])],
  [QEMU_GROUP=${withval}],
  [QEMU_GROUP=${default_qemu_group}])
AC_DEFINE_UNQUOTED([QEMU_USER], ["$QEMU_USER"], [QEMU user account])
AC_DEFINE_UNQUOTED([QEMU_GROUP], ["$QEMU_GROUP"], [QEMU group account])


AC_ARG_WITH([macvtap],
  [AS_HELP_STRING([--with-macvtap],
    [enable macvtap device @<:@default=check@:>@])],
  [with_macvtap=${withval}],
  [with_macvtap=check])

AC_MSG_CHECKING([whether to compile with macvtap support])
if test "$with_macvtap" != "no" ; then
    AC_TRY_COMPILE([ #include <sys/socket.h>
                     #include <linux/rtnetlink.h> ],
                   [ int x = MACVLAN_MODE_BRIDGE;
                     int y = IFLA_VF_MAX; ],
                   [ with_macvtap=yes ],
                   [ if test "$with_macvtap" = "yes" ; then
                         AC_MSG_ERROR([Installed linux headers don't show support for macvtap device.])
                     fi
                     with_macvtap=no ])
    if test "$with_macvtap" = "yes" ; then
        val=1
    else
        val=0
    fi
    AC_DEFINE_UNQUOTED([WITH_MACVTAP], $val, [whether macvtap support is enabled])
fi
AM_CONDITIONAL([WITH_MACVTAP], [test "$with_macvtap" = "yes"])
AC_MSG_RESULT([$with_macvtap])
if test "$with_macvtap" = yes; then
    AC_CHECK_DECLS([MACVLAN_MODE_PASSTHRU], [], [], [[
      #include <sys/socket.h>
      #include <linux/if_link.h>
    ]])
fi


AC_ARG_WITH([virtualport],
  [AS_HELP_STRING([--with-virtualport],
    [enable virtual port support @<:@default=check@:>@])],
  [with_virtualport=${withval}],
  [with_virtualport=check])

dnl Warn the user and error out if they requested virtualport support with configure
dnl options, but the required macvtap support isn't available

if test "$with_virtualport" = "yes"; then
    if test "$with_macvtap" = "no"; then
        AC_MSG_ERROR([--with-virtualport requires --with-macvtap])
    fi
fi

dnl virtualport checks

if test "$with_macvtap" != "yes"; then
    with_virtualport=no
fi
if test "$with_virtualport" != "no"; then
    AC_MSG_CHECKING([whether to compile with virtual port support])
    AC_TRY_COMPILE([ #include <sys/socket.h>
                     #include <linux/rtnetlink.h> ],
                     [ int x = IFLA_PORT_MAX; ],
                     [ with_virtualport=yes ],
                     [ if test "$with_virtualport" = "yes" ; then
                         AC_MSG_ERROR([Installed linux headers don't show support for virtual port support.])
                       fi
                       with_virtualport=no ])
    if test "$with_virtualport" = "yes"; then
        val=1
    else
        val=0
    fi
    AC_DEFINE_UNQUOTED([WITH_VIRTUALPORT], $val,
                       [whether vsi vepa support is enabled])
    AC_MSG_RESULT([$with_virtualport])
fi
AM_CONDITIONAL([WITH_VIRTUALPORT], [test "$with_virtualport" = "yes"])


dnl netlink library

have_libnl=no

if test "$with_linux" = "yes"; then
    # When linking with netcf, we must ensure that we pick the same version
    # of libnl that netcf picked.  Prefer libnl-3 unless we can prove
    # netcf linked against libnl-1, or unless the user set LIBNL_CFLAGS.
    # (Setting LIBNL_CFLAGS is already used by PKG_CHECK_MODULES to
    # override any probing, so if it set, you know which libnl is in use.)
    libnl_ldd=
    for dir in /usr/lib64 /usr/lib /usr/lib/*-linux-gnu*; do
        if test -f $dir/libnetcf.so; then
            libnl_ldd=`(ldd $dir/libnetcf.so) 2>&1`
            break
        fi
    done
    case $libnl_ldd:${LIBNL_CFLAGS+set} in
        *libnl-3.so.*:) LIBNL_REQUIRED=3.0 ;;
    esac
    case $libnl_ldd:${LIBNL_CFLAGS+set} in
        *libnl.so.1*:) ;;
        *)
        PKG_CHECK_MODULES([LIBNL], [libnl-3.0], [
            have_libnl=yes
            AC_DEFINE([HAVE_LIBNL3], [1], [Use libnl-3.0])
            AC_DEFINE([HAVE_LIBNL], [1], [whether the netlink library is available])
            PKG_CHECK_MODULES([LIBNL_ROUTE3], [libnl-route-3.0])
            LIBNL_CFLAGS="$LIBNL_CFLAGS $LIBNL_ROUTE3_CFLAGS"
            LIBNL_LIBS="$LIBNL_LIBS $LIBNL_ROUTE3_LIBS"
        ], [:]) ;;
    esac
    if test "$have_libnl" = no; then
        PKG_CHECK_MODULES([LIBNL], [libnl-1 >= $LIBNL_REQUIRED], [
            have_libnl=yes
            AC_DEFINE_UNQUOTED([HAVE_LIBNL], [1],
             [whether the netlink library is available])
            AC_DEFINE_UNQUOTED([HAVE_LIBNL1], [1],
             [whether the netlink v1 library is available])
        ], [
            if test "$with_macvtap" = "yes"; then
                AC_MSG_ERROR([libnl-devel >= $LIBNL_REQUIRED is required for macvtap support])
            fi
        ])
    fi
fi
AM_CONDITIONAL([HAVE_LIBNL], [test "$have_libnl" = "yes"])

AC_SUBST([LIBNL_CFLAGS])
AC_SUBST([LIBNL_LIBS])

# Check for Linux vs. BSD ifreq members
AC_CHECK_MEMBERS([struct ifreq.ifr_newname,
                  struct ifreq.ifr_ifindex,
                  struct ifreq.ifr_index],
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
        Makefile src/Makefile include/Makefile docs/Makefile \
        docs/schemas/Makefile \
        gnulib/lib/Makefile \
        gnulib/tests/Makefile \
        libvirt.pc libvirt.spec mingw-libvirt.spec \
        po/Makefile.in \
        include/libvirt/Makefile include/libvirt/libvirt.h \
        daemon/Makefile \
        tools/Makefile \
        tests/Makefile \
        examples/apparmor/Makefile \
        examples/domain-events/events-c/Makefile \
        examples/domsuspend/Makefile \
        examples/dominfo/Makefile \
        examples/openauth/Makefile \
        examples/hellolibvirt/Makefile \
        examples/systemtap/Makefile \
        examples/xml/nwfilter/Makefile])
AC_OUTPUT

AC_MSG_NOTICE([])
AC_MSG_NOTICE([Configuration summary])
AC_MSG_NOTICE([=====================])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Drivers])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([      Xen: $with_xen])
AC_MSG_NOTICE([     QEMU: $with_qemu])
AC_MSG_NOTICE([      UML: $with_uml])
AC_MSG_NOTICE([   OpenVZ: $with_openvz])
AC_MSG_NOTICE([   VMware: $with_vmware])
AC_MSG_NOTICE([     VBox: $with_vbox])
AC_MSG_NOTICE([   XenAPI: $with_xenapi])
AC_MSG_NOTICE([ xenlight: $with_libxl])
AC_MSG_NOTICE([      LXC: $with_lxc])
AC_MSG_NOTICE([     PHYP: $with_phyp])
AC_MSG_NOTICE([      ESX: $with_esx])
AC_MSG_NOTICE([  Hyper-V: $with_hyperv])
AC_MSG_NOTICE([Parallels: $with_parallels])
AC_MSG_NOTICE([     Test: $with_test])
AC_MSG_NOTICE([   Remote: $with_remote])
AC_MSG_NOTICE([  Network: $with_network])
AC_MSG_NOTICE([ Libvirtd: $with_libvirtd])
AC_MSG_NOTICE([Interface: $with_interface])
AC_MSG_NOTICE([  macvtap: $with_macvtap])
AC_MSG_NOTICE([ virtport: $with_virtualport])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Storage Drivers])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([     Dir: $with_storage_dir])
AC_MSG_NOTICE([      FS: $with_storage_fs])
AC_MSG_NOTICE([   NetFS: $with_storage_fs])
AC_MSG_NOTICE([     LVM: $with_storage_lvm])
AC_MSG_NOTICE([   iSCSI: $with_storage_iscsi])
AC_MSG_NOTICE([    SCSI: $with_storage_scsi])
AC_MSG_NOTICE([   mpath: $with_storage_mpath])
AC_MSG_NOTICE([    Disk: $with_storage_disk])
AC_MSG_NOTICE([     RBD: $with_storage_rbd])
AC_MSG_NOTICE([Sheepdog: $with_storage_sheepdog])
AC_MSG_NOTICE([ Gluster: $with_storage_gluster])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Security Drivers])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([ SELinux: $with_secdriver_selinux ($SELINUX_MOUNT)])
AC_MSG_NOTICE([AppArmor: $with_secdriver_apparmor])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Driver Loadable Modules])
AC_MSG_NOTICE([])
if test "$with_driver_modules" != "no" ; then
AC_MSG_NOTICE([  dlopen: $DRIVER_MODULE_CFLAGS $DRIVER_MODULE_LIBS])
else
AC_MSG_NOTICE([  dlopen: no])
fi
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Libraries])
AC_MSG_NOTICE([])
LIBVIRT_RESULT_APPARMOR
LIBVIRT_RESULT_ATTR
LIBVIRT_RESULT_AUDIT
LIBVIRT_RESULT_AVAHI
LIBVIRT_RESULT_BLKID
LIBVIRT_RESULT_CAPNG
LIBVIRT_RESULT_CURL
LIBVIRT_RESULT_DBUS
LIBVIRT_RESULT_FUSE
LIBVIRT_RESULT_GLUSTER
LIBVIRT_RESULT_HAL
LIBVIRT_RESULT_NETCF
LIBVIRT_RESULT_NUMACTL
LIBVIRT_RESULT_OPENWSMAN
LIBVIRT_RESULT_PCIACCESS
LIBVIRT_RESULT_READLINE
LIBVIRT_RESULT_SANLOCK
LIBVIRT_RESULT_SASL
LIBVIRT_RESULT_SELINUX
LIBVIRT_RESULT_SSH2
LIBVIRT_RESULT_UDEV
LIBVIRT_RESULT_YAJL
AC_MSG_NOTICE([  libxml: $LIBXML_CFLAGS $LIBXML_LIBS])
AC_MSG_NOTICE([  dlopen: $DLOPEN_LIBS])
if test "$with_hyperv" = "yes" ; then
AC_MSG_NOTICE([openwsman: $OPENWSMAN_CFLAGS $OPENWSMAN_LIBS])
else
AC_MSG_NOTICE([openwsman: no])
fi
if test "$with_gnutls" != "no" ; then
AC_MSG_NOTICE([  gnutls: $GNUTLS_CFLAGS $GNUTLS_LIBS])
else
AC_MSG_NOTICE([  gnutls: no])
fi
AC_MSG_NOTICE([firewalld: $with_firewalld])
if test "$with_polkit" = "yes" ; then
if test "$with_polkit0" = "yes" ; then
AC_MSG_NOTICE([  polkit: $POLKIT_CFLAGS $POLKIT_LIBS (version 0)])
else
AC_MSG_NOTICE([  polkit: $PKCHECK_PATH (version 1)])
fi
else
AC_MSG_NOTICE([  polkit: no])
fi
if test "$with_xen" = "yes" ; then
AC_MSG_NOTICE([     xen: $XEN_CFLAGS $XEN_LIBS])
else
AC_MSG_NOTICE([     xen: no])
fi
if test "$with_xenapi" = "yes" ; then
AC_MSG_NOTICE([  xenapi: $LIBXENSERVER_CFLAGS $LIBXENSERVER_LIBS])
else
AC_MSG_NOTICE([  xenapi: no])
fi
if test "$with_libxl" = "yes" ; then
AC_MSG_NOTICE([xenlight: $LIBXL_CFLAGS $LIBXL_LIBS])
else
AC_MSG_NOTICE([xenlight: no])
fi
if test "$with_qemu" = "yes" && test "$LIBPCAP_FOUND" != "no"; then
AC_MSG_NOTICE([    pcap: $LIBPCAP_CFLAGS $LIBPCAP_LIBS])
else
AC_MSG_NOTICE([    pcap: no])
fi
if test "$have_libnl" = "yes" ; then
AC_MSG_NOTICE([      nl: $LIBNL_CFLAGS $LIBNL_LIBS])
else
AC_MSG_NOTICE([      nl: no])
fi
if test "$with_vbox" = "yes" && test -n "$MSCOM_LIBS" ; then
AC_MSG_NOTICE([   mscom: $MSCOM_LIBS])
else
AC_MSG_NOTICE([   mscom: no])
fi
if test "$with_remote" = "yes" || test "$with_libvirtd" = "yes" ; then
AC_MSG_NOTICE([     xdr: $XDR_CFLAGS])
else
AC_MSG_NOTICE([     xdr: no])
fi
if test "$with_storage_rbd" = "yes" ; then
AC_MSG_NOTICE([     rbd: $LIBRBD_LIBS])
else
AC_MSG_NOTICE([     rbd: no])
fi

AC_MSG_NOTICE([])
AC_MSG_NOTICE([Test suite])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([   Coverage: $enable_coverage])
AC_MSG_NOTICE([  Alloc OOM: $enable_oom])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Miscellaneous])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([            Debug: $enable_debug])
AC_MSG_NOTICE([      Use -Werror: $set_werror])
AC_MSG_NOTICE([    Warning Flags: $WARN_CFLAGS])
AC_MSG_NOTICE([           DTrace: $with_dtrace])
AC_MSG_NOTICE([            numad: $with_numad])
AC_MSG_NOTICE([      XML Catalog: $XML_CATALOG_FILE])
AC_MSG_NOTICE([      Init script: $with_init_script])
AC_MSG_NOTICE([Char device locks: $with_chrdev_lock_files])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Privileges])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([      QEMU: $QEMU_USER:$QEMU_GROUP])
AC_MSG_NOTICE([])
