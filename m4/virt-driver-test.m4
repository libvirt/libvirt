dnl The test driver
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

AC_DEFUN([LIBVIRT_DRIVER_ARG_TEST], [
  LIBVIRT_ARG_WITH_FEATURE([TEST], [test driver], [yes])
])

AC_DEFUN([LIBVIRT_DRIVER_CHECK_TEST], [
  if test "$with_test" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_TEST], 1, [whether Test driver is enabled])
  fi
  AM_CONDITIONAL([WITH_TEST], [test "$with_test" = "yes"])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_TEST], [
  LIBVIRT_RESULT([Test], [$with_test])
])
