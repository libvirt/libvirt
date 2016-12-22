dnl The interface driver
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

AC_DEFUN([LIBVIRT_DRIVER_ARG_INTERFACE], [
  LIBVIRT_ARG_WITH_FEATURE([INTERFACE], [host interface driver], [check])
])

AC_DEFUN([LIBVIRT_DRIVER_CHECK_INTERFACE], [
  AC_REQUIRE([LIBVIRT_DRIVER_CHECK_LIBVIRTD])
  AC_REQUIRE([LIBVIRT_CHECK_NETCF])
  AC_REQUIRE([LIBVIRT_CHECK_UDEV])

  dnl Don't compile the interface driver without libvirtd
  if test "$with_libvirtd" = "no" ; then
    with_interface=no
  fi

  dnl The interface driver depends on the netcf library or udev library
  case $with_interface:$with_netcf:$with_udev in
    check:*yes*) with_interface=yes ;;
    check:no:no) with_interface=no ;;
    yes:no:no) AC_MSG_ERROR([Requested the Interface driver without netcf or udev support]) ;;
  esac

  if test "$with_interface" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_INTERFACE], [1], [whether the interface driver is enabled])
  fi
  AM_CONDITIONAL([WITH_INTERFACE], [test "$with_interface" = "yes"])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_INTERFACE], [
  LIBVIRT_RESULT([Interface], [$with_interface])
])
