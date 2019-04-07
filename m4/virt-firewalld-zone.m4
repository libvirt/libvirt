dnl firewalld_zone check - whether or not to install the firewall "libvirt" zone
dnl
dnl Copyright (C) 2019 Red Hat, Inc.
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

AC_DEFUN([LIBVIRT_ARG_FIREWALLD_ZONE], [
  LIBVIRT_ARG_WITH([FIREWALLD_ZONE], [Whether to install firewalld libvirt zone], [check])
])

AC_DEFUN([LIBVIRT_CHECK_FIREWALLD_ZONE], [
  AC_REQUIRE([LIBVIRT_CHECK_FIREWALLD])
  AC_MSG_CHECKING([for whether to install firewalld libvirt zone])

  if test "x$with_firewalld_zone" = "xcheck" ; then
    with_firewalld_zone=$with_firewalld
  fi

  if test "x$with_firewalld_zone" = "xyes" ; then
    if test "x$with_firewalld" != "xyes" ; then
      AC_MSG_ERROR([You must have firewalld support enabled to enable firewalld-zone])
    fi
    AC_DEFINE_UNQUOTED([WITH_FIREWALLD_ZONE], [1], [whether firewalld libvirt zone is installed])
  fi

  AM_CONDITIONAL([WITH_FIREWALLD_ZONE], [test "x$with_firewalld_zone" != "xno"])
  AC_MSG_RESULT($with_firewalld_zone)
])

AC_DEFUN([LIBVIRT_RESULT_FIREWALLD_ZONE], [
  LIBVIRT_RESULT([firewalld-zone], [$with_firewalld_zone])
])
