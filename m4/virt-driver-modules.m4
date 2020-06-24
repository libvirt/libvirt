dnl The driver module support
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

AC_DEFUN([LIBVIRT_CHECK_DRIVER_MODULES], [
  AC_REQUIRE([LIBVIRT_CHECK_DLOPEN])

  with_driver_modules=$with_libvirtd

  DRIVER_MODULES_CFLAGS=
  if test "$with_driver_modules" = "yes"; then
    if test "$with_dlfcn" != "yes" || test "$with_dlopen" != "yes"; then
      AC_MSG_ERROR([You must have dlfcn.h / dlopen() support to build driver modules])
    fi

    DRIVER_MODULES_LDFLAGS="-export-dynamic"
  fi
  AC_SUBST([DRIVER_MODULES_LDFLAGS])
])

AC_DEFUN([LIBVIRT_RESULT_DRIVER_MODULES], [
  LIBVIRT_RESULT_LIB([DRIVER_MODULES])
])
