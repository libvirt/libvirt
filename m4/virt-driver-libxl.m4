dnl The libxl driver
dnl
dnl Copyright (C) 2016 Red Hat, Inc.
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
dnl

AC_DEFUN([LIBVIRT_DRIVER_ARG_LIBXL], [
  LIBVIRT_ARG_WITH_FEATURE([LIBXL], [libxenlight], [check])
])

AC_DEFUN([LIBVIRT_DRIVER_CHECK_LIBXL], [
  LIBXL_LIBS=""
  LIBXL_CFLAGS=""
  LIBXL_FIRMWARE_DIR=""
  LIBXL_EXECBIN_DIR=""
  LIBXL_API_VERSION="-DLIBXL_API_VERSION=0x040500"

  dnl search for libxl, aka libxenlight
  old_with_libxl="$with_libxl"
  LIBVIRT_CHECK_PKG([LIBXL], [xenlight], [4.6.0], [true])
  if test "x$with_libxl" = "xyes" ; then
    LIBXL_FIRMWARE_DIR=$($PKG_CONFIG --variable xenfirmwaredir xenlight)
    LIBXL_EXECBIN_DIR=$($PKG_CONFIG --variable libexec_bin xenlight)
  fi

  dnl In Fedora <= 28, the xenlight pkgconfig file is in the -runtime package
  dnl https://bugzilla.redhat.com/show_bug.cgi?id=1629643
  dnl Until Fedora 28 reaches EOL, fallback to lib probe if xenlight.pc is
  dnl not found
  if test "x$with_libxl" = "xno" ; then
    with_libxl="$old_with_libxl"

    save_CFLAGS="$CFLAGS"
    CFLAGS="$CFLAGS $LIBXL_API_VERSION"
    LIBVIRT_CHECK_LIB([LIBXL], [xenlight], [libxl_cpupool_cpuadd_cpumap], [libxl.h], [fail="1"])
    CFLAGS="$save_CFLAGS"

    if test $fail = 1; then
      AC_MSG_ERROR([You must install the libxl Library from Xen >= 4.6 to compile libxenlight driver with -lxl])
    fi
  fi

  if test "$with_libxl" = "yes"; then
    LIBXL_CFLAGS="$LIBXL_CFLAGS $LIBXL_API_VERSION"

    dnl If building with libxl, use the libxl utility header and lib too
    AC_CHECK_HEADERS([libxlutil.h])
    LIBXL_LIBS="$LIBXL_LIBS -lxlutil"
    if test "x$LIBXL_FIRMWARE_DIR" != "x"; then
      AC_DEFINE_UNQUOTED([LIBXL_FIRMWARE_DIR], ["$LIBXL_FIRMWARE_DIR"], [directory containing Xen firmware blobs])
    fi
    if test "x$LIBXL_EXECBIN_DIR" != "x"; then
      AC_DEFINE_UNQUOTED([LIBXL_EXECBIN_DIR], ["$LIBXL_EXECBIN_DIR"], [directory containing Xen libexec binaries])
    fi
    dnl Check if the xtl_* infrastructure is in libxentoollog
    dnl (since Xen 4.7) if not then assume it is in libxenctrl
    dnl (as it was for 4.6 and earler)
    AC_CHECK_LIB([xentoollog], [xtl_createlogger_stdiostream], [
      LIBXL_LIBS="$LIBXL_LIBS -lxenstore -lxentoollog"
    ],[
      LIBXL_LIBS="$LIBXL_LIBS -lxenstore -lxenctrl"
    ])
  fi

  dnl Check if Xen has support for PVH
  AC_CHECK_DECL(LIBXL_DOMAIN_TYPE_PVH, [AC_DEFINE([HAVE_XEN_PVH], [1], [Define to 1 if Xen has PVH support.])], [], [#include <libxl.h>])

  AC_SUBST([LIBXL_CFLAGS])
  AC_SUBST([LIBXL_LIBS])
])

AC_DEFUN([LIBVIRT_RESULT_LIBXL], [
  LIBVIRT_RESULT_LIB([LIBXL])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_LIBXL], [
  LIBVIRT_RESULT([libxl], [$with_libxl])
])
