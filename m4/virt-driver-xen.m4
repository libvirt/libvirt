dnl The XEN driver
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

AC_DEFUN([LIBVIRT_DRIVER_ARG_XEN], [
  LIBVIRT_ARG_WITH_FEATURE([XEN], [XEN], [check])
  LIBVIRT_ARG_WITH_FEATURE([XEN_INOTIFY], [XEN inotify], [check])
])

AC_DEFUN([LIBVIRT_DRIVER_CHECK_XEN], [
  old_LIBS="$LIBS"
  old_CFLAGS="$CFLAGS"
  XEN_LIBS=""
  XEN_CFLAGS=""

  dnl search for the Xen store library
  if test "$with_xen" != "no" ; then
    if test "$with_xen" != "yes" && test "$with_xen" != "check" ; then
      XEN_CFLAGS="-I$with_xen/include"
      XEN_LIBS="-L$with_xen/lib64 -L$with_xen/lib"
    fi
    fail=0
    CFLAGS="$CFLAGS $XEN_CFLAGS"
    LIBS="$LIBS $XEN_LIBS"
    AC_CHECK_LIB([xenstore], [xs_read], [
           with_xen=yes
           XEN_LIBS="$XEN_LIBS -lxenstore"
       ],[
           if test "$with_xen" = "yes"; then
             fail=1
           fi
           with_xen=no
       ])
  fi

  if test "$with_xen" != "no" ; then
    dnl In Xen 4.2, xs.h is deprecated in favor of xenstore.h.
    AC_CHECK_HEADERS([xenstore.h])
    AC_CHECK_HEADERS([xen/xen.h xen/version.h xen/dom0_ops.h],,[
       if test "$with_xen" = "yes"; then
         fail=1
       fi
       with_xen=no
    ],
[#include <stdio.h>
#include <stdint.h>
])
  fi

  if test "$with_xen" != "no" ; then
    dnl Search for the location of <xen/{linux,sys}/privcmd.h>.
    found=
    AC_CHECK_HEADERS([xen/sys/privcmd.h xen/linux/privcmd.h], [found=yes; break;], [],
       [#include <stdio.h>
        #include <stdint.h>
        #include <xen/xen.h>
       ])
    if test "x$found" != "xyes"; then
      if test "$with_xen" = "yes"; then
        fail=1
      fi
      with_xen=no
    fi
  fi

  LIBS="$old_LIBS"
  CFLAGS="$old_CFLAGS"

  if test $fail = 1; then
    AC_MSG_ERROR([You must install the Xen development package to compile Xen driver with -lxenstore])
  fi

  if test "$with_xen" = "yes"; then
    AC_DEFINE_UNQUOTED([WITH_XEN], 1, [whether Xen driver is enabled])
  fi

  AM_CONDITIONAL([WITH_XEN], [test "$with_xen" = "yes"])
  AC_SUBST([XEN_CFLAGS])
  AC_SUBST([XEN_LIBS])

  dnl
  dnl check for kernel headers required by xen_inotify
  dnl
  if test "$with_xen" != "yes"; then
    with_xen_inotify=no
  fi
  if test "$with_xen_inotify" != "no"; then
    AC_CHECK_HEADER([sys/inotify.h], [
        with_xen_inotify=yes
    ], [
        if test "$with_xen_inotify" = "check"; then
          with_xen_inotify=no
          AC_MSG_NOTICE([Header file <sys/inotify.h> is required for Xen Inotify support, disabling it])
        else
          AC_MSG_ERROR([Header file <sys/inotify.h> is required for Xen Inotify support!])
        fi
    0])
  fi
  if test "$with_xen_inotify" = "yes"; then
    AC_DEFINE_UNQUOTED([WITH_XEN_INOTIFY], 1, [whether Xen inotify sub-driver is enabled])
  fi
  AM_CONDITIONAL([WITH_XEN_INOTIFY], [test "$with_xen_inotify" = "yes"])
])

AC_DEFUN([LIBVIRT_RESULT_XEN], [
  LIBVIRT_RESULT_LIB([XEN])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_XEN], [
  LIBVIRT_RESULT([XEN], [$with_xen])
])
