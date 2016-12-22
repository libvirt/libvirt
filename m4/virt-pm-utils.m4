dnl The pm-utils support check
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

AC_DEFUN([LIBVIRT_ARG_PM_UTILS], [
  LIBVIRT_ARG_WITH([PM_UTILS], [use pm-utils for power management], [check])
])

AC_DEFUN([LIBVIRT_CHECK_PM_UTILS], [
  AC_REQUIRE([LIBVIRT_CHECK_DBUS])
  AC_REQUIRE([LIBVIRT_CHECK_INIT_SCRIPT])

  if test "$with_pm_utils" = "check"; then
    with_pm_utils=yes
    if test "$with_dbus" = "yes"; then
      if test "$init_systemd" = "yes"; then
        with_pm_utils=no
      fi
    fi
  fi

  if test "$with_pm_utils" = "yes"; then
    AC_DEFINE_UNQUOTED([WITH_PM_UTILS], 1, [whether to use pm-utils])
  fi
  AM_CONDITIONAL([WITH_PM_UTILS], [test "$with_pm_utils" = "yes"])
])

AC_DEFUN([LIBVIRT_RESULT_PM_UTILS], [
  LIBVIRT_RESULT_LIB([PM_UTILS])
])
