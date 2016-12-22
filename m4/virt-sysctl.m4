dnl sysctl config check
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

AC_DEFUN([LIBVIRT_ARG_SYSCTL_CONFIG], [
  LIBVIRT_ARG_WITH([SYSCTL], [Whether to install sysctl configs], [check])
])

AC_DEFUN([LIBVIRT_CHECK_SYSCTL_CONFIG], [
  AC_MSG_CHECKING([for whether to install sysctl config])
  if test "$with_sysctl" = "yes" || test "$with_sysctl" = "check"
  then
    case $host in
      *-*-linux*)
        with_sysctl=yes
        ;;
      *)
        if test "$with_sysctl" = "yes"; then
          AC_MSG_ERROR([No sysctl configuration supported for $host])
        else
          with_sysctl=no
        fi
        ;;
    esac
  fi
  AM_CONDITIONAL([WITH_SYSCTL], test "$with_sysctl" = "yes")
  AC_MSG_RESULT($with_sysctl)
])
