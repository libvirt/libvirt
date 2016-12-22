dnl The firewalld support
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

AC_DEFUN([LIBVIRT_ARG_FIREWALLD], [
  LIBVIRT_ARG_WITH_FEATURE([FIREWALLD], [firewalld], [check])
])

AC_DEFUN([LIBVIRT_CHECK_FIREWALLD], [
  AC_REQUIRE([LIBVIRT_CHECK_DBUS])

  if test "x$with_firewalld" = "xcheck" ; then
    with_firewalld=$with_dbus
  fi

  if test "x$with_firewalld" = "xyes" ; then
    if test "x$with_dbus" != "xyes" ; then
      AC_MSG_ERROR([You must have dbus enabled for firewalld support])
    fi
    AC_DEFINE_UNQUOTED([HAVE_FIREWALLD], [1], [whether firewalld support is enabled])
  fi

  AM_CONDITIONAL([HAVE_FIREWALLD], [test "x$with_firewalld" != "xno"])
])

AC_DEFUN([LIBVIRT_RESULT_FIREWALLD], [
  LIBVIRT_RESULT_LIB([FIREWALLD])
])
