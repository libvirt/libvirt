dnl The libxml-2.0 library
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

AC_DEFUN([LIBVIRT_ARG_LIBXML], [
  LIBVIRT_ARG_WITH_ALT([LIBXML], [libxml-2.0 (>= 2.6.0) location], [check])
])

AC_DEFUN([LIBVIRT_CHECK_LIBXML], [
  LIBXML_REQUIRED="2.6.0"
  LIBXML_CONFIG="xml2-config"
  LIBXML_CFLAGS=""
  LIBXML_LIBS=""
  LIBXML_FOUND="no"

  if test "x$with_libxml" = "xno" ; then
    AC_MSG_CHECKING(for libxml2 libraries >= $LIBXML_REQUIRED)
    AC_MSG_ERROR([libxml2 >= $LIBXML_REQUIRED is required for libvirt])
  elif test "x$with_libxml" = "xcheck" && test "x$PKG_CONFIG" != "x" ; then
    PKG_CHECK_MODULES(LIBXML, libxml-2.0 >= $LIBXML_REQUIRED, [LIBXML_FOUND=yes], [LIBXML_FOUND=no])
  fi
  if test "$LIBXML_FOUND" = "no" ; then
    if test "x$with_libxml" != "xcheck" ; then
      LIBXML_CONFIG=$with_libxml/bin/$LIBXML_CONFIG
    fi
    AC_MSG_CHECKING(libxml2 $LIBXML_CONFIG >= $LIBXML_REQUIRED )
    if ! $LIBXML_CONFIG --version > /dev/null 2>&1 ; then
      AC_MSG_ERROR([Could not find libxml2 anywhere (see config.log for details).])
    fi
    vers=`$LIBXML_CONFIG --version | awk -F. '{ printf "%d", ($1 * 1000 + $2) * 1000 + $3;}'`
    minvers=`echo $LIBXML_REQUIRED | awk -F. '{ printf "%d", ($1 * 1000 + $2) * 1000 + $3;}'`
    if test "$vers" -ge "$minvers" ; then
      LIBXML_LIBS="`$LIBXML_CONFIG --libs`"
      LIBXML_CFLAGS="`$LIBXML_CONFIG --cflags`"
      LIBXML_FOUND="yes"
      AC_MSG_RESULT(yes)
    else
      AC_MSG_ERROR(
        [You need at least libxml2 $LIBXML_REQUIRED for this version of libvirt])
    fi
  fi

  AC_SUBST([LIBXML_CFLAGS])
  AC_SUBST([LIBXML_LIBS])

  dnl xmlURI structure has query_raw?
  old_CFLAGS="$CFLAGS"
  old_LIBS="$LIBS"
  CFLAGS="$CFLAGS $LIBXML_CFLAGS"
  LIBS="$LIBS $LIBXML_LIBS"

  AC_CHECK_MEMBER([struct _xmlURI.query_raw],
                  [AC_DEFINE([HAVE_XMLURI_QUERY_RAW], [1],
                             [Have query_raw field in libxml2 xmlURI structure])],
                  [], [#include <libxml/uri.h>])

  CFLAGS="$old_CFLAGS"
  LIBS="$old_LIBS"
])

AC_DEFUN([LIBVIRT_RESULT_LIBXML], [
  LIBVIRT_RESULT_LIB([LIBXML])
])
