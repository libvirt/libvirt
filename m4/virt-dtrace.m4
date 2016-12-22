dnl The DTrace static probes
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

AC_DEFUN([LIBVIRT_ARG_DTRACE], [
  LIBVIRT_ARG_WITH([DTRACE], [use dtrace for static probing], [check])
])

AC_DEFUN([LIBVIRT_CHECK_DTRACE], [
  if test "$with_dtrace" != "no" ; then
    AC_PATH_PROG([DTRACE], [dtrace], [], [$LIBVIRT_SBIN_PATH])
    if test -z "$DTRACE" ; then
      if test "$with_dtrace" = "check"; then
        with_dtrace=no
      else
        AC_MSG_ERROR([You must install the 'dtrace' binary to enable libvirt static probes])
      fi
    else
      with_dtrace=yes
    fi
    if test "$with_dtrace" = "yes"; then
      AC_DEFINE_UNQUOTED([WITH_DTRACE_PROBES], 1, [whether DTrace static probes are available])
    fi
  fi
  AM_CONDITIONAL([WITH_DTRACE_PROBES], [test "$with_dtrace" != "no"])
])

AC_DEFUN([LIBVIRT_RESULT_DTRACE], [
  AC_MSG_NOTICE([            DTrace: $with_dtrace])
])
