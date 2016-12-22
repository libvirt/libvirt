dnl The AppArmor security driver
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

AC_DEFUN([LIBVIRT_SECDRIVER_ARG_APPARMOR], [
  LIBVIRT_ARG_WITH([SECDRIVER_APPARMOR], [use AppArmor security driver], [check])
])

AC_DEFUN([LIBVIRT_SECDRIVER_CHECK_APPARMOR], [
  AC_REQUIRE([LIBVIRT_CHECK_APPARMOR])

  if test "$with_apparmor" != "yes" ; then
    if test "$with_secdriver_apparmor" = "check" ; then
      with_secdriver_apparmor=no
    fi
    if test "$with_secdriver_apparmor" != "no" ; then
      AC_MSG_ERROR([You must install the AppArmor development package in order to compile libvirt])
    fi
  elif test "with_secdriver_apparmor" != "no" ; then
    with_secdriver_apparmor=yes
    AC_DEFINE_UNQUOTED([WITH_SECDRIVER_APPARMOR], 1, [whether AppArmor security driver is available])
  fi
  AM_CONDITIONAL([WITH_SECDRIVER_APPARMOR], [test "$with_secdriver_apparmor" != "no"])

  LIBVIRT_ARG_WITH([APPARMOR_PROFILES], [install apparmor profiles], [no])
  if test "$with_apparmor" = "no"; then
    with_apparmor_profiles="no"
  fi
  AM_CONDITIONAL([WITH_APPARMOR_PROFILES], [test "$with_apparmor_profiles" != "no"])
])

AC_DEFUN([LIBVIRT_SECDRIVER_RESULT_APPARMOR], [
  LIBVIRT_RESULT([AppArmor], [$with_secdriver_apparmor],
                 [install profiles: $with_apparmor_profiles])
])
