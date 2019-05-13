dnl The libudev.so library
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

AC_DEFUN([LIBVIRT_ARG_UDEV],[
  LIBVIRT_ARG_WITH_FEATURE([UDEV], [libudev], [check], [219])
])

AC_DEFUN([LIBVIRT_CHECK_UDEV],[
  AC_REQUIRE([LIBVIRT_CHECK_PCIACCESS])
  LIBVIRT_CHECK_PKG([UDEV], [libudev], [219])

  if test "$with_udev" = "yes" && test "$with_pciaccess" != "yes" ; then
    AC_MSG_ERROR([You must install the pciaccess module to build with udev])
  fi

  if test "$with_udev" = "yes" ; then
    old_CFLAGS="$CFLAGS"
    old_LIBS="$LIBS"
    CFLAGS="$CFLAGS $UDEV_CFLAGS"
    LIBS="$CFLAGS $UDEV_LIBS"
    AC_CHECK_FUNCS([udev_monitor_set_receive_buffer_size])
    CFLAGS="$old_CFLAGS"
    LIBS="$old_LIBS"
  fi
])

AC_DEFUN([LIBVIRT_RESULT_UDEV],[
  AC_REQUIRE([LIBVIRT_RESULT_PCIACCESS])
  LIBVIRT_RESULT_LIB([UDEV])
])
