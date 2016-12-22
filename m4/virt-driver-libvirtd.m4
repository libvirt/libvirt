dnl The libvirtd driver
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

AC_DEFUN([LIBVIRT_DRIVER_ARG_LIBVIRTD], [
  LIBVIRT_ARG_WITH_FEATURE([LIBVIRTD], [libvirtd], [yes])
])

AC_DEFUN([LIBVIRT_DRIVER_CHECK_LIBVIRTD], [
  if test "$with_libvirtd" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_LIBVIRTD], 1, [whether libvirtd daemon is enabled])
  fi
  AM_CONDITIONAL([WITH_LIBVIRTD], [test "$with_libvirtd" = "yes"])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_LIBVIRTD], [
  LIBVIRT_RESULT([Libvirtd], [$with_libvirtd])
])
