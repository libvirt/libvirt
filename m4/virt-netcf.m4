dnl The libnetcf.so library
dnl
dnl Copyright (C) 2012-2013 Red Hat, Inc.
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

AC_DEFUN([LIBVIRT_CHECK_NETCF],[
  LIBVIRT_CHECK_PKG([NETCF], [netcf], [0.1.4])

  if test "$with_netcf" = "yes" ; then
    old_CFLAGS="$CFLAGS"
    old_LIBS="$CFLAGS"
    CFLAGS="$CFLAGS $NETCF_CFLAGS"
    LIBS="$LIBS $NETCF_LIBS"
    AC_CHECK_FUNC([ncf_change_begin], [netcf_transactions=1], [netcf_transactions=0])
    if test "$netcf_transactions" = "1" ; then
        AC_DEFINE_UNQUOTED([HAVE_NETCF_TRANSACTIONS], [1],
          [we have sufficiently new version of netcf for transaction network API])
    fi
    CFLAGS="$old_CFLAGS"
    LIBS="$old_LIBS"
  fi
])

AC_DEFUN([LIBVIRT_RESULT_NETCF],[
  LIBVIRT_RESULT_LIB([NETCF])
])
