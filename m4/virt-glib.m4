dnl The glib.so library
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

AC_DEFUN([LIBVIRT_ARG_GLIB], [
  LIBVIRT_ARG_WITH([GLIB], [glib-2.0 location], [check])
])

AC_DEFUN([LIBVIRT_CHECK_GLIB],[
  GLIB_REQUIRED=2.48.0

  LIBVIRT_CHECK_PKG([GLIB], [glib-2.0 gobject-2.0], [$GLIB_REQUIRED])

  if test "$with_glib" = "no" ; then
    AC_MSG_ERROR([glib-2.0, gobject-2.0 >= $GLIB_REQUIRED are required for libvirt])
  fi
])

AC_DEFUN([LIBVIRT_RESULT_GLIB], [
  LIBVIRT_RESULT_LIB([GLIB])
])
