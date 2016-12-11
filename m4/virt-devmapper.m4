dnl The devmapper library
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

AC_DEFUN([LIBVIRT_CHECK_DEVMAPPER], [
  DEVMAPPER_REQUIRED=1.0.0
  DEVMAPPER_CFLAGS=
  DEVMAPPER_LIBS=

  PKG_CHECK_MODULES([DEVMAPPER], [devmapper >= $DEVMAPPER_REQUIRED], [], [DEVMAPPER_FOUND=no])

  if test "$DEVMAPPER_FOUND" = "no"; then
    # devmapper is missing pkg-config files in ubuntu, suse, etc
    save_LIBS="$LIBS"
    save_CFLAGS="$CFLAGS"
    DEVMAPPER_FOUND=yes
    AC_CHECK_LIB([devmapper], [dm_task_run],,[DEVMAPPER_FOUND=no])
    DEVMAPPER_LIBS="-ldevmapper"
    LIBS="$save_LIBS"
    CFLAGS="$save_CFLAGS"
  fi

  AC_CHECK_HEADERS([libdevmapper.h],,[DEVMAPPER_FOUND=no])

  AC_SUBST([DEVMAPPER_CFLAGS])
  AC_SUBST([DEVMAPPER_LIBS])
])
