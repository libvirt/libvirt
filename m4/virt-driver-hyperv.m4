dnl The Hyper-V driver
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

AC_DEFUN([LIBVIRT_DRIVER_ARG_HYPERV], [
  LIBVIRT_ARG_WITH_FEATURE([HYPERV], [Hyper-V], [check])
])

AC_DEFUN([LIBVIRT_DRIVER_CHECK_HYPERV], [
  AC_REQUIRE([LIBVIRT_CHECK_OPENWSMAN])

  if test "$with_hyperv" != "no"; then
    if test "$with_openwsman" != "yes"; then
      if test "$with_hyperv" = "check"; then
        with_hyperv=no
      else
        AC_MSG_ERROR([openwsman is required for the Hyper-V driver])
      fi
    else
      with_hyperv=yes
    fi
  fi

  if test "$with_hyperv" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_HYPERV], 1, [whether Hyper-V driver is enabled])
  fi
  AM_CONDITIONAL([WITH_HYPERV], [test "$with_hyperv" = "yes"])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_HYPERV], [
  LIBVIRT_RESULT([Hyper-V], [$with_hyperv])
])
