dnl The libnl library
dnl
dnl Copyright (C) 2012-2013 Red Hat, Inc.
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

AC_DEFUN([LIBVIRT_CHECK_LIBNL], [
  AC_REQUIRE([LIBVIRT_CHECK_MACVTAP])

  with_libnl=no

  if test "$with_linux" = "yes"; then
    PKG_CHECK_MODULES([LIBNL], [libnl-3.0], [
      with_libnl=yes
      AC_DEFINE([HAVE_LIBNL], [1], [whether the netlink library is available])
      PKG_CHECK_MODULES([LIBNL_ROUTE], [libnl-route-3.0])
      LIBNL_CFLAGS="$LIBNL_CFLAGS $LIBNL_ROUTE_CFLAGS"
      LIBNL_LIBS="$LIBNL_LIBS $LIBNL_ROUTE_LIBS"
    ], [:])
  fi
  if test "$with_libnl" = no; then
    if test "$with_macvtap" = "yes"; then
        AC_MSG_ERROR([libnl3-devel is required for macvtap support])
    fi
  fi
  AM_CONDITIONAL([HAVE_LIBNL], [test "$with_libnl" = "yes"])

  AC_SUBST([LIBNL_CFLAGS])
  AC_SUBST([LIBNL_LIBS])
])

AC_DEFUN([LIBVIRT_RESULT_LIBNL], [
  LIBVIRT_RESULT_LIB([LIBNL])
])
