dnl The XDR implementation check
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

AC_DEFUN([LIBVIRT_CHECK_XDR], [
  if test x"$with_remote" = x"yes" || test x"$with_libvirtd" = x"yes"; then
    dnl On MinGW portablexdr provides XDR functions, on linux they are
    dnl provided by libtirpc and on FreeBSD/macOS there is no need to
    dnl use extra library as it's provided by libc directly.

    with_xdr="yes"

    if test "$with_win" = "yes"; then
      LIBVIRT_CHECK_LIB([XDR], [portablexdr], [xdrmem_create], [rpc/rpc.h])
    elif test "$with_linux" = "yes"; then
      LIBVIRT_CHECK_PKG([XDR], [libtirpc], [0.1.10])
    else
      AM_CONDITIONAL([WITH_XDR], [test "x$with_xdr" = "xyes"])
    fi
  fi
])

AC_DEFUN([LIBVIRT_RESULT_XDR], [
  LIBVIRT_RESULT_LIB([XDR])
])
