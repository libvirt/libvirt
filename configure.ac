dnl Process this file with autoconf to produce a configure script.

AC_INIT([libvirt], [0.8.7], [libvir-list@redhat.com], [], [http://libvirt.org])
AC_CONFIG_SRCDIR([src/libvirt.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
dnl Make automake keep quiet about wildcards & other GNUmake-isms
AM_INIT_AUTOMAKE([-Wno-portability])

# Use the silent-rules feature when possible.
m4_ifndef([AM_SILENT_RULES], [m4_define([AM_SILENT_RULES],[])])
AM_SILENT_RULES([yes])

AC_CANONICAL_HOST

LIBVIRT_MAJOR_VERSION=`echo $VERSION | awk -F. '{print $1}'`
LIBVIRT_MINOR_VERSION=`echo $VERSION | awk -F. '{print $2}'`
LIBVIRT_MICRO_VERSION=`echo $VERSION | awk -F. '{print $3}'`
LIBVIRT_VERSION=$LIBVIRT_MAJOR_VERSION.$LIBVIRT_MINOR_VERSION.$LIBVIRT_MICRO_VERSION$LIBVIRT_MICRO_VERSION_SUFFIX
LIBVIRT_VERSION_INFO=`expr $LIBVIRT_MAJOR_VERSION + $LIBVIRT_MINOR_VERSION`:$LIBVIRT_MICRO_VERSION:$LIBVIRT_MINOR_VERSION
LIBVIRT_VERSION_NUMBER=`expr $LIBVIRT_MAJOR_VERSION \* 1000000 + $LIBVIRT_MINOR_VERSION \* 1000 + $LIBVIRT_MICRO_VERSION`

AC_SUBST([LIBVIRT_MAJOR_VERSION])
AC_SUBST([LIBVIRT_MINOR_VERSION])
AC_SUBST([LIBVIRT_MICRO_VERSION])
AC_SUBST([LIBVIRT_VERSION])
AC_SUBST([LIBVIRT_VERSION_INFO])
AC_SUBST([LIBVIRT_VERSION_NUMBER])

dnl Required minimum versions of all libs we depend on
LIBXML_REQUIRED="2.6.0"
GNUTLS_REQUIRED="1.0.25"
AVAHI_REQUIRED="0.6.0"
POLKIT_REQUIRED="0.6"
PARTED_REQUIRED="1.8.0"
NETCF_REQUIRED="0.1.4"
UDEV_REQUIRED=145
PCIACCESS_REQUIRED=0.10.0
XMLRPC_REQUIRED=1.14.0
HAL_REQUIRED=0.5.0
DEVMAPPER_REQUIRED=1.0.0
LIBCURL_REQUIRED="7.18.0"
LIBPCAP_REQUIRED="1.0.0"
LIBNL_REQUIRED="1.1"

dnl Checks for C compiler.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_CPP

gl_EARLY
gl_INIT

AM_PROG_CC_STDC
AC_TYPE_UID_T

dnl Make sure we have an ANSI compiler
AM_C_PROTOTYPES
test "x$U" != "x" && AC_MSG_ERROR([Compiler not ANSI compliant])

dnl Support building Win32 DLLs (must appear *before* AM_PROG_LIBTOOL)
AC_LIBTOOL_WIN32_DLL

AM_PROG_LIBTOOL
AM_PROG_CC_C_O
AM_PROG_LD

VERSION_SCRIPT_FLAGS=-Wl,--version-script=
`$LD --help 2>&1 | grep -- --version-script >/dev/null` || \
    VERSION_SCRIPT_FLAGS="-Wl,-M -Wl,"

LIBVIRT_COMPILE_WARNINGS([maximum])

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


dnl Availability of various common functions (non-fatal if missing).
AC_CHECK_FUNCS_ONCE([cfmakeraw regexec sched_getaffinity getuid getgid initgroups \
 posix_fallocate mmap])

dnl Availability of various not common threadsafe functions
AC_CHECK_FUNCS_ONCE([strerror_r getmntent_r getgrnam_r getpwuid_r])

dnl Availability of pthread functions (if missing, win32 threading is
dnl assumed).  Because of $LIB_PTHREAD, we cannot use AC_CHECK_FUNCS_ONCE.
dnl LIB_PTHREAD was set during gl_INIT by gnulib.
old_LIBS=$LIBS
LIBS="$LIBS $LIB_PTHREAD"
AC_CHECK_FUNCS([pthread_sigmask pthread_mutexattr_init])
LIBS=$old_libs

dnl Availability of various common headers (non-fatal if missing).
AC_CHECK_HEADERS([pwd.h paths.h regex.h sys/syslimits.h sys/un.h \
  sys/poll.h syslog.h mntent.h net/ethernet.h linux/magic.h \
  sys/un.h sys/syscall.h])

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
AC_PATH_PROG([BRCTL], [brctl], [brctl],
	[/sbin:/usr/sbin:/usr/local/sbin:$PATH])
AC_PATH_PROG([UDEVADM], [udevadm], [],
	[/sbin:/usr/sbin:/usr/local/sbin:$PATH])
AC_PATH_PROG([UDEVSETTLE], [udevsettle], [],
	[/sbin:/usr/sbin:/usr/local/sbin:$PATH])
AC_PATH_PROG([MODPROBE], [modprobe], [],
	[/sbin:/usr/sbin:/usr/local/sbin:$PATH])

AC_DEFINE_UNQUOTED([DNSMASQ],["$DNSMASQ"],
        [Location or name of the dnsmasq program])
AC_DEFINE_UNQUOTED([RADVD],["$RADVD"],
        [Location or name of the radvd program])
AC_DEFINE_UNQUOTED([BRCTL],["$BRCTL"],
        [Location or name of the brctl program (see bridge-utils)])
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

dnl Specific dir for HTML output ?
AC_ARG_WITH([html-dir], [AC_HELP_STRING([--with-html-dir=path],
            [path to base html directory, default $datadir/doc/html])],
            [HTML_DIR=$withval], [HTML_DIR='$(datadir)/doc'])

AC_ARG_WITH([html-subdir], [AC_HELP_STRING([--with-html-subdir=path],
            [directory used under html-dir, default $PACKAGE-$VERSION/html])],
            [test "x$withval" != "x" && HTML_DIR="$HTML_DIR/$withval"],
            [HTML_DIR="$HTML_DIR/\$(PACKAGE)-\$(VERSION)/html"])
AC_SUBST([HTML_DIR])

dnl Specific XML catalog file for validation of generated html
AC_ARG_WITH([xml-catalog-file],
            [AC_HELP_STRING([--with-xml-catalog-file=path],
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

dnl Make some notes about which OS we're compiling for, as the lxc and qemu
dnl drivers require linux headers, while storage_mpath and nwfilter are also
dnl linux specific.  The "network" and storage_fs drivers are known to not
dnl work on MacOS X presently, so we also make a note if compiling for that

with_linux=no with_osx=no
case $host in
  *-*-linux*) with_linux=yes ;;
  *-*-darwin*) with_osx=yes ;;
esac

if test $with_linux = no; then
    if test "x$with_lxc" != xyes
    then
        with_lxc=no
    fi
    if test "x$with_qemu" != xyes
    then
        with_qemu=no
    fi
fi

AM_CONDITIONAL([WITH_LINUX], [test "$with_linux" = "yes"])

dnl Allow to build without Xen, QEMU/KVM, test or remote driver
AC_ARG_WITH([xen],
  AC_HELP_STRING([--with-xen], [add XEN support @<:@default=check@:>@]),[],[with_xen=check])
AC_ARG_WITH([xen-inotify],
  AC_HELP_STRING([--with-xen-inotify], [add XEN inotify support @<:@default=check@:>@]),[],[with_xen_inotify=check])
AC_ARG_WITH([qemu],
  AC_HELP_STRING([--with-qemu], [add QEMU/KVM support @<:@default=yes@:>@]),[],[with_qemu=yes])
AC_ARG_WITH([uml],
  AC_HELP_STRING([--with-uml], [add UML support @<:@default=check@:>@]),[],[with_uml=check])
AC_ARG_WITH([openvz],
  AC_HELP_STRING([--with-openvz], [add OpenVZ support @<:@default=yes@:>@]),[],[with_openvz=yes])
AC_ARG_WITH([vmware],
  AC_HELP_STRING([--with-vmware], [add VMware support @<:@default=yes@:>@]),[],[with_vmware=yes])
AC_ARG_WITH([libssh2],
  AC_HELP_STRING([--with-libssh2=@<:@PFX@:>@], [libssh2 location @<:@default=/usr/local/lib@:>@]),[],[with_libssh2=yes])
AC_ARG_WITH([phyp],
  AC_HELP_STRING([--with-phyp], [add PHYP support @<:@default=check@:>@]),[],[with_phyp=check])
AC_ARG_WITH([xenapi],
  AC_HELP_STRING([--with-xenapi], [add XenAPI support @<:@default=check@:>@]),[],[with_xenapi=check])
AC_ARG_WITH([vbox],
  AC_HELP_STRING([--with-vbox=@<:@PFX@:>@],
                 [VirtualBox XPCOMC location @<:@default=yes@:>@]),[],
                 [with_vbox=yes])
AC_ARG_WITH([lxc],
  AC_HELP_STRING([--with-lxc], [add Linux Container support @<:@default=check@:>@]),[],[with_lxc=check])
AC_ARG_WITH([one],
  AC_HELP_STRING([--with-one], [add ONE support @<:@default=check@:>@]),[],[with_one=check])
AC_ARG_WITH([esx],
  AC_HELP_STRING([--with-esx], [add ESX support @<:@default=check@:>@]),[],[with_esx=check])
AC_ARG_WITH([test],
  AC_HELP_STRING([--with-test], [add test driver support @<:@default=yes@:>@]),[],[with_test=yes])
AC_ARG_WITH([remote],
  AC_HELP_STRING([--with-remote], [add remote driver support @<:@default=yes@:>@]),[],[with_remote=yes])
AC_ARG_WITH([libvirtd],
  AC_HELP_STRING([--with-libvirtd], [add libvirtd support @<:@default=yes@:>@]),[],[with_libvirtd=yes])

dnl
dnl in case someone want to build static binaries
dnl STATIC_BINARIES="-static"
dnl
STATIC_BINARIES=
AC_SUBST([STATIC_BINARIES])

dnl --enable-debug=(yes|no)
AC_ARG_ENABLE([debug],
              [AC_HELP_STRING([--enable-debug=@<:@no|yes@:>@],
                             [enable debugging output @<:@default=yes@:>@])],[],[enable_debug=yes])
AM_CONDITIONAL([ENABLE_DEBUG], test x"$enable_debug" = x"yes")
if test x"$enable_debug" = x"yes"; then
   AC_DEFINE([ENABLE_DEBUG], [], [whether debugging is enabled])
fi


AC_MSG_CHECKING([where to write libvirtd PID file])
AC_ARG_WITH([remote-pid-file], [AC_HELP_STRING([--with-remote-pid-file=@<:@pidfile|none@:>@], [PID file for libvirtd])])
if test "x$with_remote_pid_file" = "x" ; then
   REMOTE_PID_FILE="$localstatedir/run/libvirtd.pid"
elif test "x$with_remote_pid_file" = "xnone" ; then
   REMOTE_PID_FILE=""
else
   REMOTE_PID_FILE="$with_remote_pid_file"
fi
AC_SUBST([REMOTE_PID_FILE])
AC_MSG_RESULT($REMOTE_PID_FILE)

dnl
dnl init script flavor
dnl
AC_MSG_CHECKING([for init script flavor])
AC_ARG_WITH([init-script],
            [AC_HELP_STRING([--with-init-script=@<:@redhat|auto|none@:>@],
		     [Style of init script to install @<:@default=auto@:>@])])
if test "x$with_init_script" = "x" || test "x$with_init_script" = "xauto"; then
    if test "$cross_compiling" = yes || test ! -f /etc/redhat-release; then
        with_init_script=none
    else
        with_init_script=redhat
    fi
fi
AM_CONDITIONAL([LIBVIRT_INIT_SCRIPT_RED_HAT], test x$with_init_script = xredhat)
AC_MSG_RESULT($with_init_script)

dnl RHEL-5 has a peculiar version of Xen, which requires some special casing
AC_ARG_WITH([rhel5-api],
	[AC_HELP_STRING([--with-rhel5-api=@<:@ARG@:>@],
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


if test "$with_openvz" = "yes"; then
    AC_DEFINE_UNQUOTED([WITH_OPENVZ], 1, [whether OpenVZ driver is enabled])
fi
AM_CONDITIONAL([WITH_OPENVZ], [test "$with_openvz" = "yes"])

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
    dnl or none (most Unix)
    AC_CHECK_LIB([portablexdr],[xdrmem_create],[],[
        AC_SEARCH_LIBS([xdrmem_create],[rpc xdr nsl],[],
            [AC_MSG_ERROR([Cannot find a XDR library])])
        ])

    dnl check for cygwin's variation in xdr function names
    AC_CHECK_FUNCS([xdr_u_int64_t],[],[],[#include <rpc/xdr.h>])

    dnl Cygwin requires -I/usr/include/tirpc for <rpc/rpc.h>
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
    AC_SEARCH_LIBS([dlopen], [dl],,)
    case $ac_cv_search_dlopen:$host_os in
      'none required'* | *:mingw* | *:msvc*) DLOPEN_LIBS= ;;
      no*) AC_MSG_ERROR([Unable to find dlopen()]) ;;
      *) DLOPEN_LIBS=$ac_cv_search_dlopen ;;
    esac
    AC_SUBST([DLOPEN_LIBS])

    case "$host" in
      *-*-mingw* | *-*-msvc*) MSCOM_LIBS="-lole32 -loleaut32" ;;
      *) MSCOM_LIBS= ;;
    esac
    AC_SUBST([MSCOM_LIBS])

    AC_DEFINE_UNQUOTED([WITH_VBOX], 1, [whether VirtualBox driver is enabled])
fi
AM_CONDITIONAL([WITH_VBOX], [test "$with_vbox" = "yes"])

if test "$with_libvirtd" = "no" ; then
  with_qemu=no
fi
if test "$with_qemu" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_QEMU], 1, [whether QEMU driver is enabled])
fi
AM_CONDITIONAL([WITH_QEMU], [test "$with_qemu" = "yes"])

if test "$with_one" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_ONE],1,[whether ONE driver is enabled])
fi
AM_CONDITIONAL([WITH_ONE],[test "$with_one" = "yes"])

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
        with_xenapi=yes
        LIBXENSERVER_LIBS="$LIBXENSERVER_LIBS -lxenserver"
    ],[
        if test "$with_xenapi" = "yes"; then
            fail=1
        fi
            with_xenapi=no
    ])
fi

LIBS="$old_LIBS"
CFLAGS="$old_CFLAGS"

if test $fail = 1; then
    AC_MSG_ERROR([You must install the XenServer Library to compile XenAPI driver with -lxenserver])
fi

if test "$with_xenapi" = "yes"; then
    AC_DEFINE_UNQUOTED([WITH_XENAPI], 1, [whether XenAPI driver is enabled])
fi

AC_SUBST([LIBXENSERVER_CFLAGS])
AC_SUBST([LIBXENSERVER_LIBS])


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
    AC_TRY_LINK([#define _GNU_SOURCE
        #include <sched.h>
    ], [
        unshare (1);
    ], [
        with_lxc=yes
    ], [
        if test "$with_lxc" = "check"; then
            with_lxc=no
            AC_MSG_NOTICE([Function unshare() not present in <sched.h> header but required for LXC driver, disabling it])
        else
            AC_MSG_ERROR([Function unshare() not present in <sched.h> header, but required for LXC driver])
        fi
    ])
fi
if test "$with_lxc" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_LXC], 1, [whether LXC driver is enabled])
fi
AM_CONDITIONAL([WITH_LXC], [test "$with_lxc" = "yes"])

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
if test "$with_qemu" = "yes" || test "$with_lxc" = "yes" ; then
  AC_CHECK_HEADERS([linux/param.h linux/sockios.h linux/if_bridge.h linux/if_tun.h],,
                   AC_MSG_ERROR([You must install kernel-headers in order to compile libvirt with QEMU or LXC support]))
fi


dnl Need to test if pkg-config exists
PKG_PROG_PKG_CONFIG

dnl OpenNebula driver Compilation setting
dnl

if test "$with_libvirtd" = "no" ; then
  with_one=no
fi
XMLRPC_CFLAGS=
XMLRPC_LIBS=
if test "x$with_one" = "xyes" || test "x$with_one" = "xcheck"; then
    PKG_CHECK_MODULES(XMLRPC, xmlrpc_client >= $XMLRPC_REQUIRED,
      [with_one=yes], [
      if test "x$with_one" = "xcheck" ; then
          with_one=no
      else
          AC_MSG_ERROR(
            [You must install XMLRPC-C >= $XMLRPC_REQUIRED to compile libvirt ONE driver])
      fi
    ])
    if test "x$with_one" = "xyes" ; then
        AC_DEFINE_UNQUOTED([HAVE_XMLRPC], 1,
          [whether One is used to broadcast server presence])
    fi
fi
AM_CONDITIONAL([HAVE_XMLRPC], [test "x$with_one" = "xyes"])
AM_CONDITIONAL([WITH_ONE], [test "x$with_one" = "xyes"])
AC_SUBST([XMLRPC_CFLAGS])
AC_SUBST([XMLRPC_LIBS])


dnl ==========================================================================
dnl find libxml2 library, borrowed from xmlsec
dnl ==========================================================================
LIBXML_CONFIG="xml2-config"
LIBXML_CFLAGS=""
LIBXML_LIBS=""
LIBXML_FOUND="no"

AC_ARG_WITH([libxml], AC_HELP_STRING([--with-libxml=@<:@PFX@:>@], [libxml2 location]))
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
GNUTLS_CFLAGS=
GNUTLS_LIBS=
GNUTLS_FOUND=no
if test -x "$PKG_CONFIG" ; then
  PKG_CHECK_MODULES(GNUTLS, gnutls >= $GNUTLS_REQUIRED,
     [GNUTLS_FOUND=yes], [GNUTLS_FOUND=no])
fi
if test "$GNUTLS_FOUND" = "no"; then
  fail=0
  old_libs="$LIBS"
  AC_CHECK_HEADER([gnutls/gnutls.h], [], [fail=1])
  AC_CHECK_LIB([gnutls], [gnutls_handshake],[], [fail=1], [-lgcrypt])

  test $fail = 1 &&
    AC_MSG_ERROR([You must install the GnuTLS library in order to compile and run libvirt])

  dnl Not all versions of gnutls include -lgcrypt, and so we add
  dnl it explicitly for the calls to gcry_control/check_version
  GNUTLS_LIBS="$LIBS -lgcrypt"
  LIBS="$old_libs"
else
  GNUTLS_LIBS="$GNUTLS_LIBS -lgcrypt"
fi

AC_SUBST([GNUTLS_CFLAGS])
AC_SUBST([GNUTLS_LIBS])

dnl Old versions of GnuTLS uses types like 'gnutls_session' instead
dnl of 'gnutls_session_t'.  Try to detect this type if defined so
dnl that we can offer backwards compatibility.
old_cflags="$CFLAGS"
old_libs="$LIBS"
CFLAGS="$CFLAGS $GNUTLS_CFLAGS"
LIBS="$LIBS $GNUTLS_LIBS"
AC_CHECK_TYPE([gnutls_session],
	AC_DEFINE([GNUTLS_1_0_COMPAT],[],
		[enable GnuTLS 1.0 compatibility macros]),,
	[#include <gnutls/gnutls.h>])
CFLAGS="$old_cflags"
LIBS="$old_libs"


dnl Cyrus SASL
AC_ARG_WITH([sasl],
  AC_HELP_STRING([--with-sasl], [use cyrus SASL for authentication @<:@default=check@:>@]),
  [],
  [with_sasl=check])

SASL_CFLAGS=
SASL_LIBS=
if test "x$with_sasl" != "xno"; then
  if test "x$with_sasl" != "xyes" && test "x$with_sasl" != "xcheck"; then
    SASL_CFLAGS="-I$with_sasl"
    SASL_LIBS="-L$with_sasl"
  fi
  fail=0
  old_cflags="$CFLAGS"
  old_libs="$LIBS"
  CFLAGS="$CFLAGS $SASL_CFLAGS"
  LIBS="$LIBS $SASL_LIBS"
  AC_CHECK_HEADER([sasl/sasl.h],[],[
    if test "x$with_sasl" = "xcheck" ; then
        with_sasl=no
    else
        fail=1
    fi])
  if test "x$with_sasl" != "xno" ; then
    AC_CHECK_LIB([sasl2], [sasl_client_init],[
      SASL_LIBS="$SASL_LIBS -lsasl2"
      with_sasl=yes
    ],[
      AC_CHECK_LIB([sasl], [sasl_client_init],[
        SASL_LIBS="$SASL_LIBS -lsasl"
        with_sasl=yes
      ],[
        if test "x$with_sasl" = "xcheck" ; then
          with_sasl=no
        else
          fail=1
        fi
      ])
    ])
  fi
  test $fail = 1 &&
    AC_MSG_ERROR([You must install the Cyrus SASL development package in order to compile libvirt])
  CFLAGS="$old_cflags"
  LIBS="$old_libs"
  if test "x$with_sasl" = "xyes" ; then
    AC_DEFINE_UNQUOTED([HAVE_SASL], 1,
      [whether Cyrus SASL is available for authentication])
  fi
fi
AM_CONDITIONAL([HAVE_SASL], [test "x$with_sasl" = "xyes"])
AC_SUBST([SASL_CFLAGS])
AC_SUBST([SASL_LIBS])


dnl YAJL JSON library http://lloyd.github.com/yajl/
AC_ARG_WITH([yajl],
  AC_HELP_STRING([--with-yajl], [use YAJL for JSON parsing/formatting @<:@default=check@:>@]),
  [],
  [with_yajl=check])

YAJL_CFLAGS=
YAJL_LIBS=
if test "x$with_yajl" != "xno"; then
  if test "x$with_yajl" != "xyes" && test "x$with_yajl" != "xcheck"; then
    YAJL_CFLAGS="-I$with_yajl/include"
    YAJL_LIBS="-L$with_yajl/lib"
  fi
  fail=0
  old_cppflags="$CPPFLAGS"
  old_libs="$LIBS"
  CPPFLAGS="$CPPFLAGS $YAJL_CFLAGS"
  LIBS="$LIBS $YAJL_LIBS"
  AC_CHECK_HEADER([yajl/yajl_common.h],[],[
    if test "x$with_yajl" = "xcheck" ; then
        with_yajl=no
    else
        fail=1
    fi])
  if test "x$with_yajl" != "xno" ; then
    AC_CHECK_LIB([yajl], [yajl_parse],[
      YAJL_LIBS="$YAJL_LIBS -lyajl"
      with_yajl=yes
    ],[
      if test "x$with_yajl" = "xcheck" ; then
        with_yajl=no
      else
        fail=1
      fi
    ])
  fi
  test $fail = 1 &&
    AC_MSG_ERROR([You must install the YAJL development package in order to compile libvirt])
  CPPFLAGS="$old_cppflags"
  LIBS="$old_libs"
  if test "x$with_yajl" = "xyes" ; then
    AC_DEFINE_UNQUOTED([HAVE_YAJL], 1,
      [whether YAJL is available for JSON parsing/formatting])
  fi
fi
AM_CONDITIONAL([HAVE_YAJL], [test "x$with_yajl" = "xyes"])
AC_SUBST([YAJL_CFLAGS])
AC_SUBST([YAJL_LIBS])


dnl PolicyKit library
POLKIT_CFLAGS=
POLKIT_LIBS=
PKCHECK_PATH=
AC_ARG_WITH([polkit],
  AC_HELP_STRING([--with-polkit], [use PolicyKit for UNIX socket access checks @<:@default=check@:>@]),
  [],
  [with_polkit=check])

with_polkit0=no
with_polkit1=no
if test "x$with_polkit" = "xyes" || test "x$with_polkit" = "xcheck"; then
  dnl Check for new polkit first - just a binary
  AC_PATH_PROG([PKCHECK_PATH],[pkcheck], [], [/usr/sbin:$PATH])
  if test "x$PKCHECK_PATH" != "x" ; then
    AC_DEFINE_UNQUOTED([PKCHECK_PATH],["$PKCHECK_PATH"],[Location of pkcheck program])
    AC_DEFINE_UNQUOTED([HAVE_POLKIT], 1,
        [use PolicyKit for UNIX socket access checks])
    AC_DEFINE_UNQUOTED([HAVE_POLKIT1], 1,
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
      AC_DEFINE_UNQUOTED([HAVE_POLKIT], 1,
        [use PolicyKit for UNIX socket access checks])
      AC_DEFINE_UNQUOTED([HAVE_POLKIT0], 1,
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
AM_CONDITIONAL([HAVE_POLKIT], [test "x$with_polkit" = "xyes"])
AM_CONDITIONAL([HAVE_POLKIT0], [test "x$with_polkit0" = "xyes"])
AM_CONDITIONAL([HAVE_POLKIT1], [test "x$with_polkit1" = "xyes"])
AC_SUBST([POLKIT_CFLAGS])
AC_SUBST([POLKIT_LIBS])

dnl Avahi library
AC_ARG_WITH([avahi],
  AC_HELP_STRING([--with-avahi], [use avahi to advertise remote daemon @<:@default=check@:>@]),
  [],
  [with_avahi=check])

AVAHI_CFLAGS=
AVAHI_LIBS=
if test "x$with_avahi" = "xyes" || test "x$with_avahi" = "xcheck"; then
  PKG_CHECK_MODULES(AVAHI, avahi-client >= $AVAHI_REQUIRED,
    [with_avahi=yes], [
    if test "x$with_avahi" = "xcheck" ; then
       with_avahi=no
    else
       AC_MSG_ERROR(
         [You must install Avahi >= $AVAHI_REQUIRED to compile libvirt])
    fi
  ])
  if test "x$with_avahi" = "xyes" ; then
    AC_DEFINE_UNQUOTED([HAVE_AVAHI], 1,
      [whether Avahi is used to broadcast server presense])
  fi
fi
AM_CONDITIONAL([HAVE_AVAHI], [test "x$with_avahi" = "xyes"])
AC_SUBST([AVAHI_CFLAGS])
AC_SUBST([AVAHI_LIBS])

dnl Audit library
AC_ARG_WITH([audit],
  AC_HELP_STRING([--with-audit], [use audit library @<:@default=check@:>@]),
  [],
  [with_audit=check])

AUDIT_CFLAGS=
AUDIT_LIBS=
if test "$with_audit" != "no" ; then
  old_cflags="$CFLAGS"
  old_libs="$LIBS"
  if test "$with_audit" != "check" && "$with_audit" != "yes" ; then
    AUDIT_CFLAGS="-I$with_audit/include"
    AUDIT_LIBS="-L$with_audit/lib"
  fi
  CFLAGS="$CFLAGS $AUDIT_CFLAGS"
  LIBS="$LIBS $AUDIT_LIBS"
  fail=0
  AC_CHECK_HEADER([libaudit.h], [], [fail=1])
  AC_CHECK_LIB([audit], [audit_is_enabled], [], [fail=1])

  if test $fail = 1 ; then
    if test "$with_audit" = "yes" ; then
      AC_MSG_ERROR([You must install the Audit library in order to compile and run libvirt])
    else
      with_audit=no
      AUDIT_CFLAGS=
      AUDIT_LIBS=
    fi
  else
    with_audit=yes
  fi

  if test "$with_audit" = "yes" ; then
    AUDIT_LIBS="$AUDIT_LIBS -laudit"
    AC_DEFINE_UNQUOTED([HAVE_AUDIT], 1, [whether libaudit is available])
  fi

  CFLAGS="$old_cflags"
  LIBS="$old_libs"
fi
AM_CONDITIONAL([HAVE_AUDIT], [test "$with_audit" = "yes"])
AC_SUBST([AUDIT_CFLAGS])
AC_SUBST([AUDIT_LIBS])


dnl SELinux
AC_ARG_WITH([selinux],
  AC_HELP_STRING([--with-selinux], [use SELinux to manage security @<:@default=check@:>@]),
  [],
  [with_selinux=check])

SELINUX_CFLAGS=
SELINUX_LIBS=
if test "$with_selinux" != "no"; then
  old_cflags="$CFLAGS"
  old_libs="$LIBS"
  if test "$with_selinux" = "check"; then
    AC_CHECK_HEADER([selinux/selinux.h],[],[with_selinux=no])
    AC_CHECK_LIB([selinux], [fgetfilecon],[],[with_selinux=no])
    if test "$with_selinux" != "no"; then
      with_selinux="yes"
    fi
  else
    fail=0
    AC_CHECK_HEADER([selinux/selinux.h],[],[fail=1])
    AC_CHECK_LIB([selinux], [fgetfilecon],[],[fail=1])
    test $fail = 1 &&
      AC_MSG_ERROR([You must install the libselinux development package in order to compile libvirt with basic SELinux support])
  fi
  CFLAGS="$old_cflags"
  LIBS="$old_libs"
fi
if test "$with_selinux" = "yes"; then
  SELINUX_LIBS="-lselinux"
  AC_DEFINE_UNQUOTED([HAVE_SELINUX], 1, [whether basic SELinux functionality is available])
  dnl We prefer to use <selinux/label.h> and selabel_open, but can fall
  dnl back to matchpathcon for the sake of RHEL 5's version of libselinux.
  AC_CHECK_HEADERS([selinux/label.h])
fi
AM_CONDITIONAL([HAVE_SELINUX], [test "$with_selinux" != "no"])
AC_SUBST([SELINUX_CFLAGS])
AC_SUBST([SELINUX_LIBS])


AC_ARG_WITH([secdriver-selinux],
  AC_HELP_STRING([--with-secdriver-selinux], [use SELinux security driver @<:@default=check@:>@]),
  [],
  [with_secdriver_selinux=check])

if test "$with_selinux" != "yes" ; then
  if test "$with_secdriver_selinux" = "check" ; then
    with_secdriver_selinux=no
  elif test "$with_secdriver_selinux" = "yes"; then
        AC_MSG_ERROR([You must install the libselinux development package and enable SELinux with the --with-selinux=yes in order to compile libvirt --with-secdriver-selinux=yes])
  fi
else
  old_cflags="$CFLAGS"
  old_libs="$LIBS"
  CFLAGS="$CFLAGS $SELINUX_CFLAGS"
  LIBS="$CFLAGS $SELINUX_LIBS"

  fail=0
  AC_CHECK_FUNC([selinux_virtual_domain_context_path], [], [fail=1])
  AC_CHECK_FUNC([selinux_virtual_image_context_path], [], [fail=1])
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


dnl AppArmor
AC_ARG_WITH([apparmor],
  AC_HELP_STRING([--with-apparmor], [use AppArmor to manage security @<:@default=check@:>@]),
  [],
  [with_apparmor=check])

APPARMOR_CFLAGS=
APPARMOR_LIBS=
if test "$with_apparmor" != "no"; then
  old_cflags="$CFLAGS"
  old_libs="$LIBS"
  if test "$with_apparmor" = "check"; then
    AC_CHECK_HEADER([sys/apparmor.h],[],[with_apparmor=no])
    AC_CHECK_LIB([apparmor], [aa_change_profile],[],[with_apparmor=no])
    AC_CHECK_LIB([apparmor], [aa_change_hat],[],[with_apparmor=no])
    if test "$with_apparmor" != "no"; then
      with_apparmor="yes"
    fi
  else
    fail=0
    AC_CHECK_HEADER([sys/apparmor.h],[],[fail=1])
    AC_CHECK_LIB([apparmor], [aa_change_profile],[],[fail=1])
    AC_CHECK_LIB([apparmor], [aa_change_hat],[],[fail=1])
    test $fail = 1 &&
      AC_MSG_ERROR([You must install the AppArmor development package in order to compile libvirt])
  fi
  CFLAGS="$old_cflags"
  LIBS="$old_libs"
fi
if test "$with_apparmor" = "yes"; then
  APPARMOR_LIBS="-lapparmor"
  AC_DEFINE_UNQUOTED([HAVE_APPARMOR], 1, [whether AppArmor is available for security])
  AC_DEFINE_UNQUOTED([APPARMOR_DIR], "/etc/apparmor.d", [path to apparmor directory])
  AC_DEFINE_UNQUOTED([APPARMOR_PROFILES_PATH], "/sys/kernel/security/apparmor/profiles", [path to kernel profiles])
fi
AM_CONDITIONAL([HAVE_APPARMOR], [test "$with_apparmor" != "no"])
AC_SUBST([APPARMOR_CFLAGS])
AC_SUBST([APPARMOR_LIBS])


AC_ARG_WITH([secdriver-apparmor],
  AC_HELP_STRING([--with-secdriver-apparmor], [use AppArmor security driver @<:@default=check@:>@]),
  [],
  [with_secdriver_apparmor=check])

if test "$with_apparmor" != "yes" ; then
  if test "$with_secdriver_apparmor" = "check" ; then
    with_secdriver_apparmor=no
  else
    AC_MSG_ERROR([You must install the AppArmor development package in order to compile libvirt])
  fi
else
  old_cflags="$CFLAGS"
  old_libs="$LIBS"
  CFLAGS="$CFLAGS $APPARMOR_CFLAGS"
  LIBS="$CFLAGS $APPARMOR_LIBS"

  fail=0
  AC_CHECK_FUNC([change_hat], [], [fail=1])
  AC_CHECK_FUNC([aa_change_profile], [], [fail=1])
  CFLAGS="$old_cflags"
  LIBS="$old_libs"

  if test "$fail" = "1" ; then
    if test "$with_secdriver_apparmor" = "check" ; then
      with_secdriver_apparmor=no
    else
      AC_MSG_ERROR([You must install the AppArmor development package in order to compile libvirt])
    fi
  else
    with_secdriver_apparmor=yes
    AC_DEFINE_UNQUOTED([WITH_SECDRIVER_APPARMOR], 1, [whether AppArmor security driver is available])
  fi
fi
AM_CONDITIONAL([WITH_SECDRIVER_APPARMOR], [test "$with_secdriver_apparmor" != "no"])


dnl DTrace static probes
AC_ARG_WITH([dtrace],
  AC_HELP_STRING([--with-dtrace], [use dtrace for static probing @<:@default=check@:>@]),
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
    AC_DEFINE_UNQUOTED([WITH_DTRACE], 1, [whether DTrace static probes are available])
  fi
fi
AM_CONDITIONAL([WITH_DTRACE], [test "$with_dtrace" != "no"])


dnl NUMA lib
AC_ARG_WITH([numactl],
  AC_HELP_STRING([--with-numactl], [use numactl for host topology info @<:@default=check@:>@]),
  [],
  [with_numactl=check])

NUMACTL_CFLAGS=
NUMACTL_LIBS=
if test "$with_qemu" = "yes" && test "$with_numactl" != "no"; then
  old_cflags="$CFLAGS"
  old_libs="$LIBS"
  if test "$with_numactl" = "check"; then
    AC_CHECK_HEADER([numa.h],[],[with_numactl=no])
    AC_CHECK_LIB([numa], [numa_available],[],[with_numactl=no])
    if test "$with_numactl" != "no"; then
      with_numactl="yes"
    fi
  else
    fail=0
    AC_CHECK_HEADER([numa.h],[],[fail=1])
    AC_CHECK_LIB([numa], [numa_available],[],[fail=1])
    test $fail = 1 &&
      AC_MSG_ERROR([You must install the numactl development package in order to compile and run libvirt])
  fi
  CFLAGS="$old_cflags"
  LIBS="$old_libs"
fi
if test "$with_numactl" = "yes"; then
  NUMACTL_LIBS="-lnuma"
  AC_DEFINE_UNQUOTED([HAVE_NUMACTL], 1, [whether numactl is available for topology info])
fi
AM_CONDITIONAL([HAVE_NUMACTL], [test "$with_numactl" != "no"])
AC_SUBST([NUMACTL_CFLAGS])
AC_SUBST([NUMACTL_LIBS])


dnl pcap lib
LIBPCAP_CONFIG="pcap-config"
LIBPCAP_CFLAGS=""
LIBPCAP_LIBS=""
LIBPCAP_FOUND="no"

AC_ARG_WITH([libpcap], AC_HELP_STRING([--with-libpcap=@<:@PFX@:>@], [libpcap location]))
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
dnl libssh checks
dnl

if test "$with_libssh2" != "yes" && test "$with_libssh2" != "no"; then
		libssh2_path="$with_libssh2"
elif test "$with_libssh2" = "yes"; then
		libssh2_path="/usr/local/lib/"
elif test "$with_libssh2" = "no"; then
		with_phyp="no";
fi

if test "$with_phyp" = "check"; then
    AC_CHECK_LIB([ssh2],[libssh2_session_startup],[
        LIBSSH2_LIBS="$LIBSSH2_LIBS -lssh2 -L$libssh2_path"
        AC_SUBST([LIBSSH2_LIBS])
    ],[
        with_phyp="no"
        with_libssh2="no";
    ],[])

    if test "$with_phyp" != "no"; then
        AC_CHECK_HEADERS([libssh2.h],[
            with_phyp="yes"
            LIBSSH2_CFLAGS="-I/usr/local/include"
            AC_SUBST([LIBSSH2_CFLAGS])
        ],[
            with_phyp="no"
            with_libssh2="no";
        ],[
        ])
    fi

    if test "$with_phyp" != "no"; then
        saved_libs="$LIBS"
        LIBS="$LIBS -L$libssh2_path -lssh2"
        AC_TRY_LINK([#include <libssh2.h>], [
            (void) libssh2_session_block_directions(NULL);
        ], [
            AC_DEFINE_UNQUOTED([WITH_PHYP], 1, [whether IBM HMC / IVM driver is enabled])
        ], [
            with_phyp=no
            AC_MSG_NOTICE([Function libssh2_session_block_directions() not present in  your version of libssh2 but required for Phyp driver, disabling it])
        ])
        LIBS="$saved_libs"
    fi
elif test "$with_phyp" = "yes"; then
  AC_CHECK_LIB([ssh2],[libssh2_session_startup],[
        LIBSSH2_LIBS="$LIBSSH2_LIBS -lssh2 -L$libssh2_path"
        AC_SUBST([LIBSSH2_LIBS])],[
        AC_MSG_ERROR([You must install the libssh2 to compile Phyp driver.])
				])

  AC_CHECK_HEADERS([libssh2.h],[
        LIBSSH2_CFLAGS="-I/usr/local/include"
        AC_SUBST([LIBSSH2_CFLAGS])],[
        AC_MSG_ERROR([Cannot find libssh2 headers. Is libssh2 installed ?])
				],[])

  saved_libs="$LIBS"
  LIBS="$LIBS -lssh2"
  AC_TRY_LINK([#include <libssh2.h>], [
  (void) libssh2_session_block_directions(NULL);
  ], [], [
  AC_MSG_ERROR([Function libssh2_session_block_directions() not present in your version of libssh2. Need >= 1.0])
  ])
  LIBS="$saved_libs"

  AC_DEFINE_UNQUOTED([WITH_PHYP], 1,
        [whether IBM HMC / IVM driver is enabled])
fi
AM_CONDITIONAL([WITH_PHYP],[test "$with_phyp" = "yes"])

dnl libcap-ng
AC_ARG_WITH([capng],
  AC_HELP_STRING([--with-capng], [use libcap-ng to reduce libvirtd privileges @<:@default=check@:>@]),
  [],
  [with_capng=check])

dnl
dnl This check looks for 'capng_updatev' since that was
dnl introduced in 0.4.0 release which need as minimum
dnl
CAPNG_CFLAGS=
CAPNG_LIBS=
if test "$with_qemu" = "yes" && test "$with_capng" != "no"; then
  old_cflags="$CFLAGS"
  old_libs="$LIBS"
  if test "$with_capng" = "check"; then
    AC_CHECK_HEADER([cap-ng.h],[],[with_capng=no])
    AC_CHECK_LIB([cap-ng], [capng_updatev],[],[with_capng=no])
    if test "$with_capng" != "no"; then
      with_capng="yes"
    fi
  else
    fail=0
    AC_CHECK_HEADER([cap-ng.h],[],[fail=1])
    AC_CHECK_LIB([cap-ng], [capng_updatev],[],[fail=1])
    test $fail = 1 &&
      AC_MSG_ERROR([You must install the capng >= 0.4.0 development package in order to compile and run libvirt])
  fi
  CFLAGS="$old_cflags"
  LIBS="$old_libs"
fi
if test "$with_capng" = "yes"; then
  CAPNG_LIBS="-lcap-ng"
  AC_DEFINE_UNQUOTED([HAVE_CAPNG], 1, [whether capng is available for privilege reduction])
fi
AM_CONDITIONAL([HAVE_CAPNG], [test "$with_capng" != "no"])
AC_SUBST([CAPNG_CFLAGS])
AC_SUBST([CAPNG_LIBS])



dnl virsh libraries
AC_CHECK_HEADERS([readline/readline.h])

# Check for readline.
AC_CHECK_LIB([readline], [readline],
	[lv_use_readline=yes; VIRSH_LIBS="$VIRSH_LIBS -lreadline"],
	[lv_use_readline=no])

# If the above test failed, it may simply be that -lreadline requires
# some termcap-related code, e.g., from one of the following libraries.
# See if adding one of them to LIBS helps.
if test $lv_use_readline = no; then
    lv_saved_libs=$LIBS
    LIBS=
    AC_SEARCH_LIBS([tgetent], [ncurses curses termcap termlib])
    case $LIBS in
      no*) ;;  # handle "no" and "none required"
      *) # anything else is a -lLIBRARY
	# Now, check for -lreadline again, also using $LIBS.
	# Note: this time we use a different function, so that
	# we don't get a cached "no" result.
	AC_CHECK_LIB([readline], [rl_initialize],
		[lv_use_readline=yes
		 VIRSH_LIBS="$VIRSH_LIBS -lreadline $LIBS"],,
		[$LIBS])
	;;
    esac
    test $lv_use_readline = no &&
	AC_MSG_WARN([readline library not found])
    LIBS=$lv_saved_libs
fi

if test $lv_use_readline = yes; then
    AC_DEFINE_UNQUOTED([USE_READLINE], 1,
		       [whether virsh can use readline])
    READLINE_CFLAGS=-DUSE_READLINE
else
    READLINE_CFLAGS=
fi
AC_SUBST([READLINE_CFLAGS])
AC_SUBST([VIRSH_LIBS])

dnl check if the network driver should be compiled

AC_ARG_WITH([network],
  AC_HELP_STRING([--with-network], [with virtual network driver @<:@default=yes@:>@]),[],[with_network=yes])

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

dnl netcf library
AC_ARG_WITH([netcf],
  AC_HELP_STRING([--with-netcf], [libnetcf support to configure physical host network interfaces @<:@default=check@:>@]),
[], [with_netcf=check])

NETCF_CFLAGS=
NETCF_LIBS=
if test "$with_netcf" = "yes" || test "$with_netcf" = "check"; then
  PKG_CHECK_MODULES(NETCF, netcf >= $NETCF_REQUIRED,
    [with_netcf=yes], [
    if test "$with_netcf" = "check" ; then
       with_netcf=no
    else
       AC_MSG_ERROR(
         [You must install libnetcf >= $NETCF_REQUIRED to compile libvirt])
    fi
  ])
  if test "$with_netcf" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_NETCF], 1,
      [whether libnetcf is available to configure physical host network interfaces])
  fi
fi
AM_CONDITIONAL([WITH_NETCF], [test "$with_netcf" = "yes"])
AC_SUBST([NETCF_CFLAGS])
AC_SUBST([NETCF_LIBS])


with_secrets=yes
if test "$with_libvirtd" = "no"; then
  with_secrets=no
fi
if test "$with_secrets" = "yes" ; then
  AC_DEFINE_UNQUOTED([WITH_SECRETS], 1, [whether local secrets management driver is available])
fi
AM_CONDITIONAL([WITH_SECRETS], [test "$with_secrets" = "yes"])


AC_ARG_WITH([storage-fs],
  AC_HELP_STRING([--with-storage-fs], [with FileSystem backend for the storage driver @<:@default=check@:>@]),[],[with_storage_fs=check])
AC_ARG_WITH([storage-lvm],
  AC_HELP_STRING([--with-storage-lvm], [with LVM backend for the storage driver @<:@default=check@:>@]),[],[with_storage_lvm=check])
AC_ARG_WITH([storage-iscsi],
  AC_HELP_STRING([--with-storage-iscsi], [with iSCSI backend for the storage driver @<:@default=check@:>@]),[],[with_storage_iscsi=check])
AC_ARG_WITH([storage-scsi],
  AC_HELP_STRING([--with-storage-scsi], [with SCSI backend for the storage driver @<:@default=check@:>@]),[],[with_storage_scsi=check])
AC_ARG_WITH([storage-mpath],
  AC_HELP_STRING([--with-storage-mpath], [with mpath backend for the storage driver @<:@default=check@:>@]),[],[with_storage_mpath=check])
AC_ARG_WITH([storage-disk],
  AC_HELP_STRING([--with-storage-disk], [with GPartd Disk backend for the storage driver @<:@default=check@:>@]),[],[with_storage_disk=check])

with_storage_dir=yes
if test "$with_libvirtd" = "no"; then
  with_storage_dir=no
  with_storage_fs=no
  with_storage_lvm=no
  with_storage_iscsi=no
  with_storage_scsi=no
  with_storage_mpath=no
  with_storage_disk=no
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
  if test "$with_storage_fs" = "yes" ; then
    if test -z "$MOUNT" ; then AC_MSG_ERROR([We need mount for FS storage driver]) ; fi
    if test -z "$UMOUNT" ; then AC_MSG_ERROR([We need umount for FS storage driver]) ; fi
  else
    if test -z "$MOUNT" ; then with_storage_fs=no ; fi
    if test -z "$UMOUNT" ; then with_storage_fs=no ; fi

    if test "$with_storage_fs" = "check" ; then with_storage_fs=yes ; fi
  fi

  if test "$with_storage_fs" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_STORAGE_FS], 1, [whether FS backend for storage driver is enabled])
    AC_DEFINE_UNQUOTED([MOUNT],["$MOUNT"],
        [Location or name of the mount program])
    AC_DEFINE_UNQUOTED([UMOUNT],["$UMOUNT"],
        [Location or name of the mount program])
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
    AC_DEFINE_UNQUOTED([PVREMOVE],["$PVREMOVE"],[Location of pvcreate program])
    AC_DEFINE_UNQUOTED([VGREMOVE],["$VGREMOVE"],[Location of vgcreate program])
    AC_DEFINE_UNQUOTED([LVREMOVE],["$LVREMOVE"],[Location of lvcreate program])
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

if test "$with_storage_mpath" = "check" && test "$with_linux" = "yes"; then
   with_storage_mpath=yes

   AC_DEFINE_UNQUOTED([WITH_STORAGE_MPATH], 1,
     [whether mpath backend for storage driver is enabled])
fi
AM_CONDITIONAL([WITH_STORAGE_MPATH], [test "$with_storage_mpath" = "yes"])

if test "$with_storage_mpath" = "yes"; then
   DEVMAPPER_CFLAGS=
   DEVMAPPER_LIBS=
   PKG_CHECK_MODULES([DEVMAPPER], [devmapper >= $DEVMAPPER_REQUIRED], [], [DEVMAPPER_FOUND=no])
   if test "$DEVMAPPER_FOUND" = "no"; then
     # devmapper is missing pkg-config files in ubuntu, suse, etc
     save_LIBS="$LIBS"
     save_CFLAGS="$CFLAGS"
     DEVMAPPER_FOUND=yes
     AC_CHECK_HEADER([libdevmapper.h],,[DEVMAPPER_FOUND=no])
     AC_CHECK_LIB([devmapper], [dm_task_run],,[DEVMAPPER_FOUND=no])
     DEVMAPPER_LIBS="-ldevmapper"
     LIBS="$save_LIBS"
     CFLAGS="$save_CFLAGS"
   fi
   if test "$DEVMAPPER_FOUND" = "no" ; then
     AC_MSG_ERROR([You must install device-mapper-devel/libdevmapper >= $DEVMAPPER_REQUIRED to compile libvirt])
   fi

fi
AC_SUBST([DEVMAPPER_CFLAGS])
AC_SUBST([DEVMAPPER_LIBS])

LIBPARTED_CFLAGS=
LIBPARTED_LIBS=
if test "$with_storage_disk" = "yes" || test "$with_storage_disk" = "check"; then
  AC_PATH_PROG([PARTED], [parted], [], [$PATH:/sbin:/usr/sbin])
  if test -z "$PARTED" ; then
    with_storage_disk=no
    PARTED_FOUND=no
  else
    PARTED_FOUND=yes
  fi

  if test "$with_storage_disk" != "no" && test "x$PKG_CONFIG" != "x" ; then
    PKG_CHECK_MODULES(LIBPARTED, libparted >= $PARTED_REQUIRED, [], [PARTED_FOUND=no])
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

  if test "$PARTED_FOUND" = "no" ; then
    if test "$with_storage_disk" = "yes" ; then
      AC_MSG_ERROR([We need parted for disk storage driver])
    else
      with_storage_disk=no
    fi
  else
    with_storage_disk=yes
  fi

  if test "$with_storage_disk" = "yes"; then
    AC_DEFINE_UNQUOTED([WITH_STORAGE_DISK], 1, [whether Disk backend for storage driver is enabled])
    AC_DEFINE_UNQUOTED([PARTED],["$PARTED"], [Location or name of the parted program])
  fi
fi
AM_CONDITIONAL([WITH_STORAGE_DISK], [test "$with_storage_disk" = "yes"])
AC_SUBST([LIBPARTED_CFLAGS])
AC_SUBST([LIBPARTED_LIBS])

dnl
dnl check for libcurl (ESX/XenAPI)
dnl

LIBCURL_CFLAGS=""
LIBCURL_LIBS=""

if test "$with_esx" = "yes" || test "$with_esx" = "check" || test "$with_xenapi" = "yes" || test "$with_xenapi" = "check"; then
    PKG_CHECK_MODULES(LIBCURL, libcurl >= $LIBCURL_REQUIRED, [
        if test "$with_esx" = "check"; then
            with_esx=yes
        fi

        if test "$with_xenapi" = "check"; then
            with_xenapi=yes
        fi
    ], [
        if test "$with_esx" = "check"; then
            with_esx=no
            AC_MSG_NOTICE([libcurl is required for the ESX driver, disabling it])
        elif test "$with_esx" = "yes"; then
            AC_MSG_ERROR([libcurl >= $LIBCURL_REQUIRED is required for the ESX driver])
        fi

        if test "$with_xenapi" = "check"; then
            with_xenapi=no
            AC_MSG_NOTICE([libcurl is required for the XenAPI driver, disabling it])
        elif test "$with_xenapi" = "yes"; then
            AC_MSG_ERROR([libcurl >= $LIBCURL_REQUIRED is required for the XenAPI driver])
        fi
    ])
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

# XXX as of libcurl-devel-7.20.1-3.fc13.x86_64, curl ships a version
# of <curl/curl.h> that #defines several wrapper macros around underlying
# functions to add type safety for gcc only.  However, these macros
# spuriously trip gcc's -Wlogical-op warning.  Avoid the warning by
# disabling the wrappers; even if it removes some type-check safety.
LIBCURL_CFLAGS="-DCURL_DISABLE_TYPECHECK $LIBCURL_CFLAGS"

AC_SUBST([LIBCURL_CFLAGS])
AC_SUBST([LIBCURL_LIBS])

dnl
dnl check for python
dnl

AC_ARG_WITH([python],
  AC_HELP_STRING([--with-python], [Build python bindings @<:@default=yes@:>@]),[],[with_python=yes])

if test "$enable_shared:$with_python" = no:yes; then
  AC_MSG_WARN([Disabling shared libraries is incompatible with building Python extensions.])
  AC_MSG_WARN([Ignoring --with-python.])
  with_python=no
fi

PYTHON_VERSION=
PYTHON_INCLUDES=
if test "$with_python" != "no" ; then
    if test -x "$with_python/bin/python"
    then
        AC_MSG_NOTICE(Found python in $with_python/bin/python)
        PYTHON="$with_python/bin/python"
        with_python=yes
    else
        if test -x "$with_python"
        then
            AC_MSG_NOTICE(Found python in $with_python)
            PYTHON="$with_python"
            with_python=yes
        else
            if test -x "$PYTHON"
            then
                AC_MSG_NOTICE(Found python in environment PYTHON=$PYTHON)
                with_python=yes
            fi
        fi
    fi

    if test "$with_python" = "yes" ; then
        AM_PATH_PYTHON(,, [:])

        if test "$PYTHON" != : ; then
            PYTHON_CONFIG="$PYTHON-config"

            if test -x "$PYTHON_CONFIG"
            then
                PYTHON_INCLUDES=`$PYTHON_CONFIG --includes`
            else
                if test -r $PYTHON_EXEC_PREFIX/include/python$PYTHON_VERSION/Python.h
                then
                    PYTHON_INCLUDES=-I$PYTHON_EXEC_PREFIX/include/python$PYTHON_VERSION
                else
                    if test -r $prefix/include/python$PYTHON_VERSION/Python.h
                    then
                        PYTHON_INCLUDES=-I$prefix/include/python$PYTHON_VERSION
                    else
                        if test -r /usr/include/python$PYTHON_VERSION/Python.h
                        then
                            PYTHON_INCLUDES=-I/usr/include/python$PYTHON_VERSION
                        else
                            AC_MSG_NOTICE([Could not find python$PYTHON_VERSION/Python.h, disabling bindings])
                            with_python=no
                        fi
                    fi
                fi
            fi
        else
            AC_MSG_NOTICE([Could not find python interpreter, disabling bindings])
            with_python=no
        fi
    else
        AC_MSG_NOTICE([Could not find python in $with_python, disabling bindings])
        with_python=no
    fi
fi
AM_CONDITIONAL([WITH_PYTHON], [test "$with_python" = "yes"])
AC_SUBST([PYTHON_VERSION])
AC_SUBST([PYTHON_INCLUDES])



AC_MSG_CHECKING([whether this host is running a Xen kernel])
RUNNING_XEN=
if test -d /proc/sys/xen
then
    RUNNING_XEN=yes
else
    RUNNING_XEN=no
fi
AC_MSG_RESULT($RUNNING_XEN)

AC_MSG_CHECKING([If XenD UNIX socket /var/run/xend/xmlrpc.sock is accessible])
RUNNING_XEND=
if test -S /var/run/xend/xmlrpc.sock
then
    RUNNING_XEND=yes
else
    RUNNING_XEND=no
fi
AC_MSG_RESULT($RUNNING_XEND)

AM_CONDITIONAL([ENABLE_XEN_TESTS], [test "$RUNNING_XEN" != "no" && test "$RUNNING_XEND" != "no"])

AC_ARG_ENABLE([test-coverage],
  AC_HELP_STRING([--enable-test-coverage], [turn on code coverage instrumentation @<:@default=no@:>@]),
[case "${enableval}" in
   yes|no) ;;
   *)      AC_MSG_ERROR([bad value ${enableval} for test-coverage option]) ;;
 esac],
              [enableval=no])
enable_coverage=$enableval

if test "${enable_coverage}" = yes; then
  COMPILER_FLAGS=
  gl_COMPILER_FLAGS(-fprofile-arcs)
  gl_COMPILER_FLAGS(-ftest-coverage)
  AC_SUBST([COVERAGE_CFLAGS], [$COMPILER_FLAGS])
  AC_SUBST([COVERAGE_LDFLAGS], [$COMPILER_FLAGS])
  COMPILER_FLAGS=
fi

AC_ARG_ENABLE([test-oom],
  AC_HELP_STRING([--enable-test-oom], [memory allocation failure checking @<:@default=no@:>@]),
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
  AC_HELP_STRING([--enable-test-locking], [thread locking tests using CIL @<:@default=no@:>@]),
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

dnl Check for gettext
AM_GNU_GETTEXT_VERSION([0.14.1])
AM_GNU_GETTEXT([external])
dnl Since we're using such an old version of gettext, we must also define
dnl this symbol, in order to make the autopoint-supplied Makefile.in.in
dnl work properly.
AC_SUBST([MKINSTALLDIRS], ["\$(top_builddir)/$ac_aux_dir/mkinstalldirs"])

ALL_LINGUAS=`cd "$srcdir/po" > /dev/null && ls *.po | sed 's+\.po$++'`

dnl Extra link-time flags for Cygwin.
dnl Copied from libxml2 configure.in, but I removed mingw changes
dnl for now since I'm not supporting mingw at present.  - RWMJ
CYGWIN_EXTRA_LDFLAGS=
CYGWIN_EXTRA_LIBADD=
CYGWIN_EXTRA_PYTHON_LIBADD=
MINGW_EXTRA_LDFLAGS=
WIN32_EXTRA_CFLAGS=
LIBVIRT_SYMBOL_FILE=libvirt.syms
LIBVIRT_QEMU_SYMBOL_FILE='$(srcdir)/libvirt_qemu.syms'
case "$host" in
  *-*-cygwin*)
    CYGWIN_EXTRA_LDFLAGS="-no-undefined"
    CYGWIN_EXTRA_LIBADD="${INTLLIBS}"
    if test "x$PYTHON_VERSION" != "x"; then
      CYGWIN_EXTRA_PYTHON_LIBADD="-L/usr/lib/python${PYTHON_VERSION}/config -lpython${PYTHON_VERSION}"
    fi
    ;;
  *-*-mingw*)
    MINGW_EXTRA_LDFLAGS="-no-undefined"
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
AC_SUBST([CYGWIN_EXTRA_PYTHON_LIBADD])
AC_SUBST([MINGW_EXTRA_LDFLAGS])
AC_SUBST([WIN32_EXTRA_CFLAGS])
AC_SUBST([LIBVIRT_SYMBOL_FILE])
AC_SUBST([LIBVIRT_QEMU_SYMBOL_FILE])
AC_SUBST([VERSION_SCRIPT_FLAGS])


dnl Look for windres to build a Windows icon resource.
case "$host" in
  *-*-mingw* | *-*-cygwin* | *-*-msvc* )
    AC_CHECK_TOOL([WINDRES], [windres], [])
    ;;
esac
AM_CONDITIONAL([WITH_WIN_ICON], [test "$WINDRES" != ""])


dnl Driver-Modules library
AC_ARG_WITH([driver-modules],
  AC_HELP_STRING([--with-driver-modules], [build drivers as loadable modules @<:@default=no@:>@]),
  [],
  [with_driver_modules=no])

DRIVER_MODULE_CFLAGS=
DRIVER_MODULE_LIBS=
if test "x$with_driver_modules" = "xyes" ; then
  old_cflags="$CFLAGS"
  old_libs="$LIBS"
  fail=0
  AC_CHECK_HEADER([dlfcn.h],[],[fail=1])
  AC_SEARCH_LIBS([dlopen], [dl], [], [fail=1])
  test $fail = 1 &&
      AC_MSG_ERROR([You must have dlfcn.h / dlopen() support to build driver modules])

  CFLAGS="$old_cflags"
  LIBS="$old_libs"
fi
if test "$with_driver_modules" = "yes"; then
  DRIVER_MODULE_CFLAGS="-export-dynamic"
  case $ac_cv_search_dlopen in
    no*) DRIVER_MODULE_LIBS= ;;
    *) DRIVER_MODULE_LIBS=$ac_cv_search_dlopen ;;
  esac
  AC_DEFINE_UNQUOTED([WITH_DRIVER_MODULES], 1, [whether to build drivers as modules])
fi
AM_CONDITIONAL([WITH_DRIVER_MODULES], [test "$with_driver_modules" != "no"])
AC_SUBST([DRIVER_MODULE_CFLAGS])
AC_SUBST([DRIVER_MODULE_LIBS])


# Set LV_LIBTOOL_OBJDIR to "." or $lt_cv_objdir, depending on whether
# we're building shared libraries.  This is the name of the directory
# in which .o files will be created.
test "$enable_shared" = no && lt_cv_objdir=.
LV_LIBTOOL_OBJDIR=${lt_cv_objdir-.}
AC_SUBST([LV_LIBTOOL_OBJDIR])

dnl HAL library check for host device enumeration
HAL_CFLAGS=
HAL_LIBS=
AC_ARG_WITH([hal],
  AC_HELP_STRING([--with-hal], [use HAL for host device enumeration @<:@default=check@:>@]),
  [],
  [with_hal=check])

if test "$with_libvirtd" = "no" ; then
  with_hal=no
fi
if test "x$with_hal" = "xyes" || test "x$with_hal" = "xcheck"; then
  PKG_CHECK_MODULES(HAL, hal >= $HAL_REQUIRED,
    [with_hal=yes], [
    if test "x$with_hal" = "xcheck" ; then
       with_hal=no
    else
       AC_MSG_ERROR(
         [You must install hal-devel >= $HAL_REQUIRED to compile libvirt])
    fi
  ])
  if test "x$with_hal" = "xyes" ; then
    old_CFLAGS=$CFLAGS
    old_LIBS=$LIBS
    CFLAGS="$CFLAGS $HAL_CFLAGS"
    LIBS="$LIBS $HAL_LIBS"
    AC_CHECK_FUNCS([libhal_get_all_devices],,[with_hal=no])
    AC_CHECK_FUNCS([dbus_watch_get_unix_fd])
    CFLAGS="$old_CFLAGS"
    LIBS="$old_LIBS"
  fi
  if test "x$with_hal" = "xyes" ; then
    AC_DEFINE_UNQUOTED([HAVE_HAL], 1,
      [use HAL for host device enumeration])
  fi
fi
AM_CONDITIONAL([HAVE_HAL], [test "x$with_hal" = "xyes"])
AC_SUBST([HAL_CFLAGS])
AC_SUBST([HAL_LIBS])


dnl udev/libpciaccess library check for alternate host device enumeration
UDEV_CFLAGS=
UDEV_LIBS=
PCIACCESS_CFLAGS=
PCIACCESS_LIBS=
AC_ARG_WITH([udev],
  AC_HELP_STRING([--with-udev], [use libudev for host device enumeration @<:@default=check@:>@]),
  [],
  [with_udev=check])

if test "$with_libvirtd" = "no" ; then
  with_udev=no
fi
if test "x$with_udev" = "xyes" || test "x$with_udev" = "xcheck"; then
  PKG_CHECK_MODULES(UDEV, libudev >= $UDEV_REQUIRED,
    [], [
    if test "x$with_udev" = "xcheck" ; then
       with_udev=no
    else
       AC_MSG_ERROR(
         [You must install libudev-devel >= $UDEV_REQUIRED to compile libvirt])
    fi
  ])
  if test "x$with_udev" != "xno"; then
    PKG_CHECK_MODULES(PCIACCESS, pciaccess >= $PCIACCESS_REQUIRED,
      [with_udev=yes],
      [
        if test "x$with_udev" = "xcheck" ; then
          with_udev=no
        else
          AC_MSG_ERROR(
           [You must install libpciaccess-devel >= $PCIACCESS_REQUIRED to compile libvirt])
        fi
      ])
  fi
  if test "x$with_udev" = "xyes" ; then
    AC_DEFINE_UNQUOTED([HAVE_UDEV], 1,
      [use UDEV for host device enumeration])
  fi
fi
AM_CONDITIONAL([HAVE_UDEV], [test "x$with_udev" = "xyes"])
AC_SUBST([UDEV_CFLAGS])
AC_SUBST([UDEV_LIBS])
AC_SUBST([PCIACCESS_CFLAGS])
AC_SUBST([PCIACCESS_LIBS])

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

AC_ARG_WITH([qemu-user],
  AC_HELP_STRING([--with-qemu-user], [username to run QEMU system instance as @<:@default=root@:>@]),
  [QEMU_USER=${withval}],
  [QEMU_USER=root])
AC_ARG_WITH([qemu-group],
  AC_HELP_STRING([--with-qemu-group], [groupname to run QEMU system instance as @<:@default=root@:>@]),
  [QEMU_GROUP=${withval}],
  [QEMU_GROUP=root])
AC_DEFINE_UNQUOTED([QEMU_USER], ["$QEMU_USER"], [QEMU user account])
AC_DEFINE_UNQUOTED([QEMU_GROUP], ["$QEMU_GROUP"], [QEMU group account])


AC_ARG_WITH([macvtap],
  AC_HELP_STRING([--with-macvtap],[enable macvtap device @<:@default=check@:>@]),
  [with_macvtap=${withval}],
  [with_macvtap=check])

AC_MSG_CHECKING([whether to compile with macvtap support])
if test "$with_macvtap" != "no" ; then
    AC_TRY_COMPILE([ #include <sys/socket.h>
                     #include <linux/rtnetlink.h> ],
                   [ int x = MACVLAN_MODE_BRIDGE; ],
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

AC_ARG_WITH([virtualport],
  AC_HELP_STRING([--with-virtualport],[enable virtual port support @<:@default=check@:>@]),
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

LIBNL_CFLAGS=""
LIBNL_LIBS=""

if test "$with_macvtap" = "yes"; then
    PKG_CHECK_MODULES([LIBNL], [libnl-1 >= $LIBNL_REQUIRED], [
    ], [
        AC_MSG_ERROR([libnl-devel >= $LIBNL_REQUIRED is required for macvtap support])
    ])
fi

AC_SUBST([LIBNL_CFLAGS])
AC_SUBST([LIBNL_LIBS])




# Only COPYING.LIB is under version control, yet COPYING
# is included as part of the distribution tarball.
# Copy one to the other, but only if this is a srcdir-build.
# You are unlikely to be doing distribution-related things in a non-srcdir build
test "x$srcdir" = x. && ! test -f COPYING &&
cp -f COPYING.LIB COPYING

# Detect when running under the clang static analyzer's scan-build driver
# or Coverity-prevent's cov-build.  Define STATIC_ANALYSIS accordingly.
test -n "$CCC_ANALYZER_ANALYSIS$COVERITY_BUILD_COMMAND" && t=1 || t=0
AC_DEFINE_UNQUOTED([STATIC_ANALYSIS], [$t],
  [Define to 1 when performing static analysis.])

AC_OUTPUT(Makefile src/Makefile include/Makefile docs/Makefile \
	  docs/schemas/Makefile \
	  gnulib/lib/Makefile \
	  gnulib/tests/Makefile \
          libvirt.pc libvirt.spec mingw32-libvirt.spec \
          po/Makefile.in \
	  include/libvirt/Makefile include/libvirt/libvirt.h \
	  python/Makefile python/tests/Makefile \
          daemon/Makefile \
          tools/Makefile \
          tests/Makefile \
          examples/apparmor/Makefile \
          examples/domain-events/events-c/Makefile \
          examples/domsuspend/Makefile \
          examples/dominfo/Makefile \
          examples/openauth/Makefile \
          examples/python/Makefile \
          examples/hellolibvirt/Makefile \
          examples/systemtap/Makefile \
          examples/xml/nwfilter/Makefile)

AC_MSG_NOTICE([])
AC_MSG_NOTICE([Configuration summary])
AC_MSG_NOTICE([=====================])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Drivers])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([     Xen: $with_xen])
AC_MSG_NOTICE([    QEMU: $with_qemu])
AC_MSG_NOTICE([     UML: $with_uml])
AC_MSG_NOTICE([  OpenVZ: $with_openvz])
AC_MSG_NOTICE([  VMware: $with_vmware])
AC_MSG_NOTICE([    VBox: $with_vbox])
AC_MSG_NOTICE([  XenAPI: $with_xenapi])
AC_MSG_NOTICE([     LXC: $with_lxc])
AC_MSG_NOTICE([    PHYP: $with_phyp])
AC_MSG_NOTICE([     ONE: $with_one])
AC_MSG_NOTICE([     ESX: $with_esx])
AC_MSG_NOTICE([    Test: $with_test])
AC_MSG_NOTICE([  Remote: $with_remote])
AC_MSG_NOTICE([ Network: $with_network])
AC_MSG_NOTICE([Libvirtd: $with_libvirtd])
AC_MSG_NOTICE([   netcf: $with_netcf])
AC_MSG_NOTICE([ macvtap: $with_macvtap])
AC_MSG_NOTICE([virtport: $with_virtualport])
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
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Security Drivers])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([ SELinux: $with_secdriver_selinux])
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
AC_MSG_NOTICE([  libxml: $LIBXML_CFLAGS $LIBXML_LIBS])
if test "$with_esx" = "yes" ; then
AC_MSG_NOTICE([ libcurl: $LIBCURL_CFLAGS $LIBCURL_LIBS])
else
AC_MSG_NOTICE([ libcurl: no])
fi
if test "$with_libssh2" != "no" ; then
AC_MSG_NOTICE([ libssh2: $LIBSSH2_CFLAGS $LIBSSH2_LIBS])
else
AC_MSG_NOTICE([ libssh2: no])
fi
AC_MSG_NOTICE([  gnutls: $GNUTLS_CFLAGS $GNUTLS_LIBS])
if test "$with_sasl" != "no" ; then
AC_MSG_NOTICE([    sasl: $SASL_CFLAGS $SASL_LIBS])
else
AC_MSG_NOTICE([    sasl: no])
fi
if test "$with_yajl" != "no" ; then
AC_MSG_NOTICE([    yajl: $YAJL_CFLAGS $YAJL_LIBS])
else
AC_MSG_NOTICE([    yajl: no])
fi
if test "$with_avahi" = "yes" ; then
AC_MSG_NOTICE([   avahi: $AVAHI_CFLAGS $AVAHI_LIBS])
else
AC_MSG_NOTICE([   avahi: no])
fi
if test "$with_polkit" = "yes" ; then
if test "$with_polkit0" = "yes" ; then
AC_MSG_NOTICE([  polkit: $POLKIT_CFLAGS $POLKIT_LIBS (version 0)])
else
AC_MSG_NOTICE([  polkit: $PKCHECK_PATH (version 1)])
fi
else
AC_MSG_NOTICE([  polkit: no])
fi
if test "$with_audit" = "yes" ; then
AC_MSG_NOTICE([   audit: $AUDIT_CFLAGS $AUDIT_LIBS])
else
AC_MSG_NOTICE([   audit: no])
fi
if test "$with_selinux" = "yes" ; then
AC_MSG_NOTICE([ selinux: $SELINUX_CFLAGS $SELINUX_LIBS])
else
AC_MSG_NOTICE([ selinux: no])
fi
if test "$with_apparmor" = "yes" ; then
AC_MSG_NOTICE([apparmor: $APPARMOR_CFLAGS $APPARMOR_LIBS])
else
AC_MSG_NOTICE([apparmor: no])
fi
if test "$with_numactl" = "yes" ; then
AC_MSG_NOTICE([ numactl: $NUMACTL_CFLAGS $NUMACTL_LIBS])
else
AC_MSG_NOTICE([ numactl: no])
fi
if test "$with_capng" = "yes" ; then
AC_MSG_NOTICE([   capng: $CAPNG_CFLAGS $CAPNG_LIBS])
else
AC_MSG_NOTICE([   capng: no])
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
if test "$with_hal" = "yes" ; then
AC_MSG_NOTICE([     hal: $HAL_CFLAGS $HAL_LIBS])
else
AC_MSG_NOTICE([     hal: no])
fi
if test "$with_udev" = "yes" ; then
AC_MSG_NOTICE([    udev: $UDEV_CFLAGS $UDEV_LIBS $PCIACCESS_CFLAGS $PCIACCESS_LIBS])
else
AC_MSG_NOTICE([    udev: no])
fi
if test "$with_netcf" = "yes" ; then
AC_MSG_NOTICE([   netcf: $NETCF_CFLAGS $NETCF_LIBS])
else
AC_MSG_NOTICE([   netcf: no])
fi
if test "$with_one" = "yes" ; then
AC_MSG_NOTICE([  xmlrpc: $XMLRPC_CFLAGS $XMLRPC_LIBS])
else
AC_MSG_NOTICE([  xmlrpc: no])
fi
if test "$with_qemu" = "yes" && test "$LIBPCAP_FOUND" != "no"; then
AC_MSG_NOTICE([    pcap: $LIBPCAP_CFLAGS $LIBPCAP_LIBS])
else
AC_MSG_NOTICE([    pcap: no])
fi
if test "$with_macvtap" = "yes" ; then
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
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Test suite])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([   Coverage: $enable_coverage])
AC_MSG_NOTICE([  Alloc OOM: $enable_oom])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Miscellaneous])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([        Debug: $enable_debug])
AC_MSG_NOTICE([     Warnings: $enable_compile_warnings])
AC_MSG_NOTICE([     Readline: $lv_use_readline])
AC_MSG_NOTICE([       Python: $with_python])
AC_MSG_NOTICE([       DTrace: $with_dtrace])
AC_MSG_NOTICE([  XML Catalog: $XML_CATALOG_FILE])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([Privileges])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([      QEMU: $QEMU_USER:$QEMU_GROUP])
AC_MSG_NOTICE([])
