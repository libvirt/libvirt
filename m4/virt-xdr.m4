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
  with_xdr="no"
  if test x"$with_remote" = x"yes" || test x"$with_libvirtd" = x"yes"; then
    dnl Where are the XDR functions?
    dnl If portablexdr is installed, prefer that.
    dnl Otherwise try -lxdr (some MinGW)
    dnl -ltirpc (glibc 2.13.90 or newer) or none (most Unix)
    AC_CHECK_LIB([portablexdr],[xdrmem_create],[],[
      AC_SEARCH_LIBS([xdrmem_create],[xdr tirpc],[],
        [AC_MSG_ERROR([Cannot find a XDR library])])
    ])
    with_xdr="yes"

    dnl Recent glibc requires -I/usr/include/tirpc for <rpc/rpc.h>
    old_CFLAGS=$CFLAGS
    AC_CACHE_CHECK([where to find <rpc/rpc.h>], [lv_cv_xdr_cflags], [
      for add_CFLAGS in '' '-I/usr/include/tirpc' 'missing'; do
        if test x"$add_CFLAGS" = xmissing; then
          lv_cv_xdr_cflags=missing; break
        fi
        CFLAGS="$old_CFLAGS $add_CFLAGS"
        AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <rpc/rpc.h>
        ]])], [lv_cv_xdr_cflags=${add_CFLAGS:-none}; break])
      done
    ])
    CFLAGS=$old_CFLAGS
    case $lv_cv_xdr_cflags in
      none) XDR_CFLAGS= ;;
      missing) AC_MSG_ERROR([Unable to find <rpc/rpc.h>]) ;;
      *) XDR_CFLAGS=$lv_cv_xdr_cflags ;;
    esac
    AC_SUBST([XDR_CFLAGS])
  fi
])

AC_DEFUN([LIBVIRT_RESULT_XDR], [
  LIBVIRT_RESULT_LIB([XDR])
])
