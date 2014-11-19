dnl The libdbus.so library
dnl
dnl Copyright (C) 2012-2014 Red Hat, Inc.
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

AC_DEFUN([LIBVIRT_CHECK_DBUS],[
  LIBVIRT_CHECK_PKG([DBUS], [dbus-1], [1.0.0])

  if test "$with_dbus" = "yes" ; then
    old_CFLAGS="$CFLAGS"
    old_LIBS="$LIBS"
    CFLAGS="$CFLAGS $DBUS_CFLAGS"
    LIBS="$LIBS $DBUS_LIBS"
    AC_CHECK_FUNCS([dbus_watch_get_unix_fd])
    AC_CHECK_TYPES([DBusBasicValue], [], [], [[#include <dbus/dbus.h>]])
    CFLAGS="$old_CFLAGS"
    LIBS="$old_LIBS"
  fi
])

AC_DEFUN([LIBVIRT_RESULT_DBUS],[
  LIBVIRT_RESULT_LIB([DBUS])
])
