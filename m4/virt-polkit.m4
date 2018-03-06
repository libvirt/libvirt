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

  PKCHECK_PATH=

  with_polkit1=no

  if test "x$with_polkit" = "xyes" || test "x$with_polkit" = "xcheck"; then
    dnl Check for new polkit first. We directly talk over DBus
    dnl but we use existence of pkcheck binary as a sign that
    dnl we should prefer polkit-1 over polkit-0, so we check
    dnl for it even though we don't ultimately use it
    AC_PATH_PROG([PKCHECK_PATH], [pkcheck], [], [$LIBVIRT_SBIN_PATH])
    if test "x$PKCHECK_PATH" != "x" ; then
      dnl Found pkcheck, so ensure dbus-devel is present
      if test "x$with_dbus" = "xyes" ; then
        AC_DEFINE_UNQUOTED([WITH_POLKIT], 1,
            [use PolicyKit for UNIX socket access checks])
        AC_DEFINE_UNQUOTED([WITH_POLKIT1], 1,
            [use PolicyKit for UNIX socket access checks])
        with_polkit="yes"
        with_polkit1="yes"
      else
        if test "x$with_polkit" = "xcheck" ; then
          with_polkit=no
        else
           AC_MSG_ERROR(
             [You must install dbus to compile libvirt with polkit-1])
        fi
      fi
    fi
  fi

  AM_CONDITIONAL([WITH_POLKIT], [test "x$with_polkit" = "xyes"])
  AM_CONDITIONAL([WITH_POLKIT1], [test "x$with_polkit1" = "xyes"])
])

AC_DEFUN([LIBVIRT_RESULT_POLKIT], [
  msg="$PKCHECK_PATH (version 1)"
  LIBVIRT_RESULT([polkit], [$with_polkit], [$msg])
])
