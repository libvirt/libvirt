dnl gettext utilities
dnl
dnl Copyright (C) 2018 Red Hat, Inc.
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

AC_DEFUN([LIBVIRT_ARG_NLS],[
  LIBVIRT_ARG_ENABLE([NLS], [NLS], [check])
])

AC_DEFUN([LIBVIRT_CHECK_NLS],[
  if test "x$enable_nls" != "xno"
  then
    AC_CHECK_FUNC([gettext], [], [
      AC_CHECK_LIB([intl], [gettext], [], [
        if test "x$enable_nls" = "xcheck"
	then
	  enable_nls=no
	else
          AC_MSG_ERROR([gettext() is required to build libvirt]")
	fi
      ])
    ])
  fi

  if test "x$enable_nls" != "xno"
  then
    AC_CHECK_HEADERS([libintl.h], [enable_nls=yes],[
      if test "x$enable_nls" = "xcheck"
      then
        enable_nls=no
      else
        AC_MSG_ERROR([libintl.h is required to build libvirt]")
      fi
    ])
  fi

  dnl GNU gettext tools (optional).
  AC_CHECK_PROG([XGETTEXT], [xgettext], [xgettext], [no])
  AC_CHECK_PROG([MSGFMT], [msgfmt], [msgfmt], [no])
  AC_CHECK_PROG([MSGMERGE], [msgmerge], [msgmerge], [no])

  dnl Check they are the GNU gettext tools.
  AC_MSG_CHECKING([msgfmt is GNU tool])
  if $MSGFMT --version >/dev/null 2>&1 && $MSGFMT --version | grep -q 'GNU gettext'; then
    msgfmt_is_gnu=yes
  else
    msgfmt_is_gnu=no
  fi
  AC_MSG_RESULT([$msgfmt_is_gnu])
  AM_CONDITIONAL([ENABLE_NLS], [test "x$enable_nls" = "xyes"])
  AM_CONDITIONAL([HAVE_GNU_GETTEXT_TOOLS],
    [test "x$XGETTEXT" != "xno" && test "x$MSGFMT" != "xno" && \
     test "x$MSGMERGE" != "xno" && test "x$msgfmt_is_gnu" != "xno"])
])

AC_DEFUN([LIBVIRT_RESULT_NLS],[
  LIBVIRT_RESULT([NLS], [$enable_nls])
])
