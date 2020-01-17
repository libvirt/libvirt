dnl The polkit library
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

AC_DEFUN([LIBVIRT_ARG_POLKIT], [
  LIBVIRT_ARG_WITH([POLKIT], [use PolicyKit for UNIX socket access checks],
                   [check])
])

AC_DEFUN([LIBVIRT_CHECK_POLKIT], [
  AC_REQUIRE([LIBVIRT_CHECK_DBUS])

  if test "x$with_win" = "xyes"; then
    with_polkit=no
  fi

  if test "x$with_polkit" = "xcheck"; then
    dnl For --with-polkit=check, also require the pkcheck binary, even
    dnl though we talk to polkit directly over D-Bus.
    AC_PATH_PROG([PKCHECK_PATH], [pkcheck], [], [$LIBVIRT_SBIN_PATH])
    if test "x$PKCHECK_PATH" = "x" ; then
        with_polkit="no"
    fi
  fi

  if test "x$with_polkit" = "xyes" || test "x$with_polkit" = "xcheck"; then
    dnl For --with-polkit=yes, all we need is D-Bus.
    if test "x$with_dbus" = "xyes" ; then
      AC_DEFINE_UNQUOTED([WITH_POLKIT], 1,
          [use PolicyKit for UNIX socket access checks])
      with_polkit="yes"
    else
      if test "x$with_polkit" = "xcheck" ; then
        with_polkit=no
      else
         AC_MSG_ERROR(
           [You must install dbus to compile libvirt with polkit-1])
      fi
    fi
  fi

  AM_CONDITIONAL([WITH_POLKIT], [test "x$with_polkit" = "xyes"])
])

AC_DEFUN([LIBVIRT_RESULT_POLKIT], [
  LIBVIRT_RESULT([polkit], [$with_polkit])
])
