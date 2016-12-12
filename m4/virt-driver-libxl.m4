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
  fail=0
  if test "$with_libxl" != "no" ; then
    PKG_CHECK_MODULES([LIBXL], [xenlight], [
      LIBXL_FIRMWARE_DIR=`$PKG_CONFIG --variable xenfirmwaredir xenlight`
      LIBXL_EXECBIN_DIR=`$PKG_CONFIG --variable libexec_bin xenlight`
      with_libxl=yes
    ], [LIBXL_FOUND=no])
    if test "$LIBXL_FOUND" = "no"; then
      dnl No xenlight pkg-config file
      if test "$with_libxl" != "yes" && test "$with_libxl" != "check" ; then
        LIBXL_CFLAGS="-I$with_libxl/include"
        LIBXL_LIBS="-L$with_libxl"
      fi
      CFLAGS="$CFLAGS $LIBXL_CFLAGS"
      LIBS="$LIBS $LIBXL_LIBS"
      AC_CHECK_LIB([xenlight], [libxl_ctx_alloc], [
        with_libxl=yes
        LIBXL_LIBS="$LIBXL_LIBS -lxenlight"
      ],[
        if test "$with_libxl" = "yes"; then
          fail=1
        fi
        with_libxl=no
      ])
    fi
  fi

  dnl LIBXL_API_VERSION 4.4.0 introduced a new parameter to
  dnl libxl_domain_create_restore for specifying restore parameters.
  dnl The libxl driver will make use of this new parameter for specifying
  dnl the Xen migration stream version.
  LIBXL_CFLAGS="$LIBXL_CFLAGS -DLIBXL_API_VERSION=0x040400"
  LIBS="$old_LIBS"
  CFLAGS="$old_CFLAGS"

  if test $fail = 1; then
    AC_MSG_ERROR([You must install the libxl Library from Xen >= 4.2 to compile libxenlight driver with -lxl])
  fi

  if test "$with_libxl" = "yes"; then
    dnl If building with libxl, use the libxl utility header and lib too
    AC_CHECK_HEADERS([libxlutil.h])
    LIBXL_LIBS="$LIBXL_LIBS -lxlutil"
    AC_DEFINE_UNQUOTED([WITH_LIBXL], 1, [whether libxenlight driver is enabled])
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
  AM_CONDITIONAL([WITH_LIBXL], [test "$with_libxl" = "yes"])

  AC_SUBST([LIBXL_CFLAGS])
  AC_SUBST([LIBXL_LIBS])
])

AC_DEFUN([LIBVIRT_RESULT_LIBXL], [
  LIBVIRT_RESULT_LIB([LIBXL])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_LIBXL], [
  LIBVIRT_RESULT([libxl], [$with_libxl])
])
