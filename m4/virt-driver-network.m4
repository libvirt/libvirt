dnl The network driver
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

AC_DEFUN([LIBVIRT_DRIVER_ARG_NETWORK], [
  LIBVIRT_ARG_WITH([NETWORK], [with virtual network driver], [yes])
])

AC_DEFUN([LIBVIRT_DRIVER_CHECK_NETWORK], [
  AC_REQUIRE([LIBVIRT_DRIVER_CHECK_LIBVIRTD])
  AC_REQUIRE([LIBVIRT_DRIVER_CHECK_QEMU])
  AC_REQUIRE([LIBVIRT_DRIVER_CHECK_LXC])

  dnl there's no use compiling the network driver without the libvirt
  dnl daemon, nor compiling it for MacOS X, where it breaks the compile

  if test "$with_libvirtd" = "no" || test "$with_osx" = "yes"; then
    with_network=no
  fi

  if test "$with_network" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_NETWORK], 1, [whether network driver is enabled])
  fi
  AM_CONDITIONAL([WITH_NETWORK], [test "$with_network" = "yes"])

  with_bridge=no
  if test "$with_qemu:$with_lxc:$with_network" != "no:no:no"; then
    with_bridge=yes
    AC_DEFINE_UNQUOTED([WITH_BRIDGE], 1, [whether bridge code is needed])
  fi
  AM_CONDITIONAL([WITH_BRIDGE], [test "$with_bridge" = "yes"])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_NETWORK], [
  LIBVIRT_RESULT([Network], [$with_network])
])
