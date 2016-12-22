dnl The QEMU driver
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

AC_DEFUN([LIBVIRT_DRIVER_ARG_QEMU], [
  LIBVIRT_ARG_WITH_FEATURE([QEMU], [QEMU/KVM], [yes])
  LIBVIRT_ARG_WITH([QEMU_USER], [username to run QEMU system instance as],
                   ['platform dependent'])
  LIBVIRT_ARG_WITH([QEMU_GROUP], [groupname to run QEMU system instance as],
                   ['platform dependent'])
])

AC_DEFUN([LIBVIRT_DRIVER_CHECK_QEMU], [
  if test "$with_qemu" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_QEMU], 1, [whether QEMU driver is enabled])
  fi
  AM_CONDITIONAL([WITH_QEMU], [test "$with_qemu" = "yes"])

  if test $with_freebsd = yes || test $with_osx = yes; then
    default_qemu_user=root
    default_qemu_group=wheel
  else
    default_qemu_user=root
    default_qemu_group=root
  fi

  if test "x$with_qemu_user" = "xplatform dependent" ; then
    QEMU_USER="$default_qemu_user"
  else
    QEMU_USER="$with_qemu_user"
  fi
  if test "x$with_qemu_group" = "xplatform dependent" ; then
    QEMU_GROUP="$default_qemu_group"
  else
    QEMU_GROUP="$with_qemu_group"
  fi
  AC_DEFINE_UNQUOTED([QEMU_USER], ["$QEMU_USER"], [QEMU user account])
  AC_DEFINE_UNQUOTED([QEMU_GROUP], ["$QEMU_GROUP"], [QEMU group account])

  AC_PATH_PROG([QEMU_BRIDGE_HELPER], [qemu-bridge-helper],
               [/usr/libexec/qemu-bridge-helper],
               [/usr/libexec:/usr/lib/qemu:/usr/lib])
  AC_DEFINE_UNQUOTED([QEMU_BRIDGE_HELPER], ["$QEMU_BRIDGE_HELPER"],
                     [QEMU bridge helper])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_QEMU], [
  LIBVIRT_RESULT([QEMU], [$with_qemu])
])

AC_DEFUN([LIBVIRT_RESULT_QEMU_PRIVILEGES], [
  LIBVIRT_RESULT([QEMU], [$QEMU_USER:$QEMU_GROUP])
])
