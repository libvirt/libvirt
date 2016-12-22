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

  POLKIT_REQUIRED="0.6"
  POLKIT_CFLAGS=
  POLKIT_LIBS=
  PKCHECK_PATH=

  with_polkit0=no
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
    else
      dnl Check for old polkit second - library + binary
      PKG_CHECK_MODULES(POLKIT, polkit-dbus >= $POLKIT_REQUIRED,
        [with_polkit=yes], [
        if test "x$with_polkit" = "xcheck" ; then
           with_polkit=no
        else
           AC_MSG_ERROR(
             [You must install PolicyKit >= $POLKIT_REQUIRED to compile libvirt])
        fi
      ])
      if test "x$with_polkit" = "xyes" ; then
        AC_DEFINE_UNQUOTED([WITH_POLKIT], 1,
          [use PolicyKit for UNIX socket access checks])
        AC_DEFINE_UNQUOTED([WITH_POLKIT0], 1,
          [use PolicyKit for UNIX socket access checks])

        old_CFLAGS=$CFLAGS
        old_LIBS=$LIBS
        CFLAGS="$CFLAGS $POLKIT_CFLAGS"
        LIBS="$LIBS $POLKIT_LIBS"
        AC_CHECK_FUNCS([polkit_context_is_caller_authorized])
        CFLAGS="$old_CFLAGS"
        LIBS="$old_LIBS"

        AC_PATH_PROG([POLKIT_AUTH], [polkit-auth])
        if test "x$POLKIT_AUTH" != "x"; then
          AC_DEFINE_UNQUOTED([POLKIT_AUTH],["$POLKIT_AUTH"],[Location of polkit-auth program])
        fi
        with_polkit0="yes"
      fi
    fi
  fi

  AM_CONDITIONAL([WITH_POLKIT], [test "x$with_polkit" = "xyes"])
  AM_CONDITIONAL([WITH_POLKIT0], [test "x$with_polkit0" = "xyes"])
  AM_CONDITIONAL([WITH_POLKIT1], [test "x$with_polkit1" = "xyes"])
  AC_SUBST([POLKIT_CFLAGS])
  AC_SUBST([POLKIT_LIBS])
])

AC_DEFUN([LIBVIRT_RESULT_POLKIT], [
  if test "$with_polkit0" = "yes" ; then
    msg="$POLKIT_CFLAGS $POLKIT_LIBS (version 0)"
  else
    msg="$PKCHECK_PATH (version 1)"
  fi
  LIBVIRT_RESULT([polkit], [$with_polkit], [$msg])
])
