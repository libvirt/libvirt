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
  LIBVIRT_ARG_WITH([LIBXL], [libxenlight], [check])
])

AC_DEFUN([LIBVIRT_DRIVER_CHECK_LIBXL], [
  old_LIBS="$LIBS"
  old_CFLAGS="$CFLAGS"
  LIBXL_LIBS=""
  LIBXL_CFLAGS=""
  LIBXL_FIRMWARE_DIR=""
  LIBXL_EXECBIN_DIR=""

  dnl search for libxl, aka libxenlight
  dnl Xen > 4.5 introduced a pkgconfig file, check for it first
  old_with_libxl="$with_libxl"
  LIBVIRT_CHECK_PKG([LIBXL], [xenlight], [4.2.0], [true])
  if test "x$with_libxl" = "xyes" ; then
    LIBXL_FIRMWARE_DIR=$($PKG_CONFIG --variable xenfirmwaredir xenlight)
    LIBXL_EXECBIN_DIR=$($PKG_CONFIG --variable libexec_bin xenlight)
  fi

  dnl pkgconfig file not found, fallback to lib probe
  if test "x$with_libxl" = "xno" ; then
    with_libxl="$old_with_libxl"
    LIBVIRT_CHECK_LIB([LIBXL], [xenlight], [libxl_ctx_alloc], [libxl.h], [fail="1"])
    if test $fail = 1; then
      AC_MSG_ERROR([You must install the libxl Library from Xen >= 4.2 to compile libxenlight driver with -lxl])
    fi
  fi

  dnl LIBXL_API_VERSION 4.4.0 introduced a new parameter to
  dnl libxl_domain_create_restore for specifying restore parameters.
  dnl The libxl driver will make use of this new parameter for specifying
  dnl the Xen migration stream version.
  LIBXL_CFLAGS="$LIBXL_CFLAGS -DLIBXL_API_VERSION=0x040400"
  LIBS="$old_LIBS"
  CFLAGS="$old_CFLAGS"

  if test "$with_libxl" = "yes"; then
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
      LIBXL_LIBS="$LIBXL_LIBS -lxentoollog"
    ],[
      LIBXL_LIBS="$LIBXL_LIBS -lxenctrl"
    ])
  fi

  AC_SUBST([LIBXL_CFLAGS])
  AC_SUBST([LIBXL_LIBS])
])

AC_DEFUN([LIBVIRT_RESULT_LIBXL], [
  LIBVIRT_RESULT_LIB([LIBXL])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_LIBXL], [
  LIBVIRT_RESULT([libxl], [$with_libxl])
])
