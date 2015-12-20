dnl Copyright (c) 2015 SUSE LINUX Products GmbH, Nuernberg, Germany.
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

AC_DEFUN([LIBVIRT_CHECK_LOGIN_SHELL], [
  AC_ARG_WITH([login_shell],
    [AS_HELP_STRING([--with-login-shell],
      [build virt-login-shell @<:@default=check@:>@])])
  m4_divert_text([DEFAULTS], [with_login_shell=check])

  if test "x$with_login_shell" != "xno"; then
    if test "x$with_win" = "xyes"; then
      if "x$with_login_shell" = "yes"; then
        AC_MSG_ERROR([virt-login-shell is not supported on Windows])
      else
        with_login_shell=no;
      fi
    else
      with_login_shell=yes;
    fi
  fi

  if test "x$with_login_shell" = "xyes" ; then
      AC_DEFINE_UNQUOTED([WITH_LOGIN_SHELL], 1, [whether virt-login-shell is built])
  fi
  AM_CONDITIONAL([WITH_LOGIN_SHELL], [test "$with_login_shell" = "yes"])
])
