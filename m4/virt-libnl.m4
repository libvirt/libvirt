dnl The libnl library
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

AC_DEFUN([LIBVIRT_CHECK_LIBNL], [
  AC_REQUIRE([LIBVIRT_CHECK_NETCF])
  AC_REQUIRE([LIBVIRT_CHECK_MACVTAP])

  LIBNL_REQUIRED="1.1"
  with_libnl=no

  if test "$with_linux" = "yes"; then
    # When linking with netcf, we must ensure that we pick the same version
    # of libnl that netcf picked.  Prefer libnl-3 unless we can prove
    # netcf linked against libnl-1, or unless the user set LIBNL_CFLAGS.
    # (Setting LIBNL_CFLAGS is already used by PKG_CHECK_MODULES to
    # override any probing, so if it set, you know which libnl is in use.)
    libnl_ldd=
    for dir in /usr/lib64 /usr/lib /usr/lib/*-linux-gnu*; do
      if test -f $dir/libnetcf.so; then
        libnl_ldd=`(ldd $dir/libnetcf.so) 2>&1`
        break
      fi
    done
    case $libnl_ldd:${LIBNL_CFLAGS+set} in
      *libnl-3.so.*:) LIBNL_REQUIRED=3.0 ;;
    esac
    case $libnl_ldd:${LIBNL_CFLAGS+set} in
      *libnl.so.1*:) ;;
      *)
        PKG_CHECK_MODULES([LIBNL], [libnl-3.0], [
          with_libnl=yes
          AC_DEFINE([HAVE_LIBNL3], [1], [Use libnl-3.0])
          AC_DEFINE([HAVE_LIBNL], [1], [whether the netlink library is available])
          PKG_CHECK_MODULES([LIBNL_ROUTE3], [libnl-route-3.0])
          LIBNL_CFLAGS="$LIBNL_CFLAGS $LIBNL_ROUTE3_CFLAGS"
          LIBNL_LIBS="$LIBNL_LIBS $LIBNL_ROUTE3_LIBS"
        ], [:]) ;;
    esac
    if test "$with_libnl" = no; then
      PKG_CHECK_MODULES([LIBNL], [libnl-1 >= $LIBNL_REQUIRED], [
        with_libnl=yes
        AC_DEFINE_UNQUOTED([HAVE_LIBNL], [1],
          [whether the netlink library is available])
        AC_DEFINE_UNQUOTED([HAVE_LIBNL1], [1],
          [whether the netlink v1 library is available])
      ], [
        if test "$with_macvtap" = "yes"; then
          if test "$LIBNL_REQUIRED" = "3.0";then
            AC_MSG_ERROR([libnl3-devel >= $LIBNL_REQUIRED is required for macvtap support])
          else
            AC_MSG_ERROR([libnl-devel >= $LIBNL_REQUIRED is required for macvtap support])
          fi
        fi
      ])
    fi
  fi
  AM_CONDITIONAL([HAVE_LIBNL], [test "$with_libnl" = "yes"])

  AC_SUBST([LIBNL_CFLAGS])
  AC_SUBST([LIBNL_LIBS])
])

AC_DEFUN([LIBVIRT_RESULT_LIBNL], [
  LIBVIRT_RESULT_LIB([LIBNL])
])
