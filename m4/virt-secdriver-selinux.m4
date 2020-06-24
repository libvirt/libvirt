dnl The SElinux security driver
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

AC_DEFUN([LIBVIRT_SECDRIVER_ARG_SELINUX], [
  LIBVIRT_ARG_WITH([SECDRIVER_SELINUX], [use SELinux security driver], [check])
])

AC_DEFUN([LIBVIRT_SECDRIVER_CHECK_SELINUX], [
  AC_REQUIRE([LIBVIRT_CHECK_SELINUX])

  if test "$with_selinux" != "yes" ; then
    if test "$with_secdriver_selinux" = "check" ; then
      with_secdriver_selinux=no
    fi
    if test "$with_secdriver_selinux" != "no"; then
      AC_MSG_ERROR([You must install the libselinux development package and enable SELinux with the --with-selinux=yes in order to compile libvirt --with-secdriver-selinux=yes])
    fi
  elif test "$with_secdriver_selinux" != "no"; then
    with_secdriver_selinux=yes
    AC_DEFINE_UNQUOTED([WITH_SECDRIVER_SELINUX], 1, [whether SELinux security driver is available])
  fi
  AM_CONDITIONAL([WITH_SECDRIVER_SELINUX], [test "$with_secdriver_selinux" != "no"])
])

AC_DEFUN([LIBVIRT_SECDRIVER_RESULT_SELINUX], [
  LIBVIRT_RESULT([SELinux], [$with_secdriver_selinux])
])
