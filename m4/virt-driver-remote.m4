dnl The remote driver
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

AC_DEFUN([LIBVIRT_DRIVER_ARG_REMOTE], [
  LIBVIRT_ARG_WITH_FEATURE([REMOTE], [remote driver], [yes])
  LIBVIRT_ARG_WITH([REMOTE_DEFAULT_MODE], [remote driver default mode], [legacy])
])

AC_DEFUN([LIBVIRT_DRIVER_CHECK_REMOTE], [
  if test "$with_remote" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_REMOTE], 1, [whether Remote driver is enabled])
  fi
  AM_CONDITIONAL([WITH_REMOTE], [test "$with_remote" = "yes"])

  case "$with_remote_default_mode" in
    legacy)
      REMOTE_DRIVER_MODE_DEFAULT=REMOTE_DRIVER_MODE_LEGACY
      ;;
    direct)
      REMOTE_DRIVER_MODE_DEFAULT=REMOTE_DRIVER_MODE_DIRECT
      ;;
    *)
      AC_MSG_ERROR([Unknown remote mode '$with_remote_default_mode'])
      ;;
  esac

  AC_DEFINE_UNQUOTED([REMOTE_DRIVER_MODE_DEFAULT],[$REMOTE_DRIVER_MODE_DEFAULT], [Default remote driver mode])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_REMOTE], [
  LIBVIRT_RESULT([Remote], [$with_remote])
])
