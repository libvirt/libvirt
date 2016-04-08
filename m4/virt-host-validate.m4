dnl Copyright (C) 2015 SUSE LINUX Products GmbH, Nuernberg, Germany.
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

AC_DEFUN([LIBVIRT_CHECK_HOST_VALIDATE], [
  AC_ARG_WITH([host_validate],
    [AS_HELP_STRING([--with-host-validate],
      [build virt-host-validate @<:@default=check@:>@])])
  m4_divert_text([DEFAULTS], [with_host_validate=check])

  if test "x$with_host_validate" != "xno"; then
    if test "x$with_win" = "xyes"; then
      if test "x$with_host_validate" = "xyes"; then
        AC_MSG_ERROR([virt-host-validate is not supported on Windows])
      else
        with_host_validate=no;
      fi
    else
      with_host_validate=yes;
    fi
  fi

  if test "x$with_host_validate" = "xyes" ; then
      AC_DEFINE_UNQUOTED([WITH_HOST_VALIDATE], 1, [whether virt-host-validate is built])
  fi
  AM_CONDITIONAL([WITH_HOST_VALIDATE], [test "x$with_host_validate" = "xyes"])
])
