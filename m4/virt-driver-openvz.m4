dnl The OpenVZ driver
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

AC_DEFUN([LIBVIRT_DRIVER_ARG_OPENVZ], [
  LIBVIRT_ARG_WITH_FEATURE([OPENVZ], [OpenVZ], [check])
])

AC_DEFUN([LIBVIRT_DRIVER_CHECK_OPENVZ], [
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
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_OPENVZ], [
  LIBVIRT_RESULT([OpenVZ], [$with_openvz])
])
