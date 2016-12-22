dnl The numad binary check
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

AC_DEFUN([LIBVIRT_ARG_NUMAD], [
  LIBVIRT_ARG_WITH([NUMAD], [use numad to manage CPU placement dynamically],
                   [check])
])

AC_DEFUN([LIBVIRT_CHECK_NUMAD], [
  AC_REQUIRE([LIBVIRT_CHECK_NUMACTL])

  if test "$with_numad" != "no" ; then
    fail=0

    AC_PATH_PROG([NUMAD], [numad], [], [$LIBVIRT_SBIN_PATH])

    if test "$with_numad" = "check"; then
      test "$with_numactl" = "yes" || fail=1
      if test -z "$NUMAD" || test $fail = 1; then
        with_numad="no"
      else
        with_numad="yes"
      fi
    else
      test -z  "$NUMAD" &&
        AC_MSG_ERROR([You must install numad package to manage CPU and memory placement dynamically])

      test "$with_numactl" = "yes" || fail=1
      test $fail = 1 &&
        AC_MSG_ERROR([You must install the numactl development package in order to compile and run libvirt])
    fi
  fi
  if test "$with_numad" = "yes"; then
    AC_DEFINE_UNQUOTED([HAVE_NUMAD], 1, [whether numad is available])
    AC_DEFINE_UNQUOTED([NUMAD],["$NUMAD"], [Location or name of the numad program])
  fi
  AM_CONDITIONAL([HAVE_NUMAD], [test "$with_numad" != "no"])
])

AC_DEFUN([LIBVIRT_RESULT_NUMAD], [
  AC_MSG_NOTICE([             numad: $with_numad])
])
