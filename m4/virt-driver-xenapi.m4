dnl The XenAPI driver
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

AC_DEFUN([LIBVIRT_DRIVER_ARG_XENAPI], [
  LIBVIRT_ARG_WITH([XENAPI], [XenAPI], [check])
])

AC_DEFUN([LIBVIRT_DRIVER_CHECK_XENAPI], [
  AC_REQUIRE([LIBVIRT_CHECK_CURL])

  old_LIBS="$LIBS"
  old_CFLAGS="$CFLAGS"
  XENAPI_LIBS=""
  XENAPI_CFLAGS=""
  dnl search for the XenServer library
  fail=0
  if test "$with_xenapi" != "no" ; then
    if test "$with_xenapi" != "yes" && test "$with_xenapi" != "check" ; then
      XENAPI_CFLAGS="-I$with_xenapi/include"
      XENAPI_LIBS="-L$with_xenapi"
    fi
    CFLAGS="$CFLAGS $XENAPI_CFLAGS"
    LIBS="$LIBS $XENAPI_LIBS"
    AC_CHECK_LIB([xenserver], [xen_vm_start], [
      XENAPI_LIBS="$XENAPI_LIBS -lxenserver"
    ],[
      if test "$with_xenapi" = "yes"; then
        fail=1
      fi
      with_xenapi=no
    ])
    if test "$with_xenapi" != "no" ; then
      if test "$with_curl" = "no"; then
        if test "$with_xenapi" = "yes"; then
          fail=1
        fi
        with_xenapi=no
      else
        with_xenapi=yes
      fi
    fi
  fi

  LIBS="$old_LIBS"
  CFLAGS="$old_CFLAGS"

  if test $fail = 1; then
    AC_MSG_ERROR([You must install libxenserver and libcurl to compile the XenAPI driver])
  fi

  if test "$with_xenapi" = "yes"; then
    AC_DEFINE_UNQUOTED([WITH_XENAPI], 1, [whether XenAPI driver is enabled])
  fi
  AM_CONDITIONAL([WITH_XENAPI], [test "$with_xenapi" = "yes"])

  AC_SUBST([XENAPI_CFLAGS])
  AC_SUBST([XENAPI_LIBS])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_XENAPI], [
  LIBVIRT_RESULT([XenAPI], [$with_xenapi])
])

AC_DEFUN([LIBVIRT_RESULT_XENAPI], [
  LIBVIRT_RESULT_LIB([XENAPI])
])
