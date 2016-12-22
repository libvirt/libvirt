dnl The macvtap support
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

AC_DEFUN([LIBVIRT_ARG_MACVTAP], [
  LIBVIRT_ARG_WITH([MACVTAP], [enable macvtap device], [check])
])

AC_DEFUN([LIBVIRT_CHECK_MACVTAP], [
  AC_MSG_CHECKING([whether to compile with macvtap support])
  if test "$with_macvtap" != "no" ; then
    AC_TRY_COMPILE([ #include <sys/socket.h>
                     #include <linux/rtnetlink.h> ],
                   [ int x = MACVLAN_MODE_BRIDGE;
                     int y = IFLA_VF_MAX; ],
                   [ with_macvtap=yes ],
                   [ if test "$with_macvtap" = "yes" ; then
                       AC_MSG_ERROR([Installed linux headers don't show support for macvtap device.])
                     fi
                     with_macvtap=no ])
    if test "$with_macvtap" = "yes" ; then
      val=1
    else
      val=0
    fi
    AC_DEFINE_UNQUOTED([WITH_MACVTAP], $val, [whether macvtap support is enabled])
  fi
  AM_CONDITIONAL([WITH_MACVTAP], [test "$with_macvtap" = "yes"])
  AC_MSG_RESULT([$with_macvtap])

  if test "$with_macvtap" = yes; then
    AC_CHECK_DECLS([MACVLAN_MODE_PASSTHRU], [], [], [[
      #include <sys/socket.h>
      #include <linux/if_link.h>
    ]])
  fi
])

AC_DEFUN([LIBVIRT_RESULT_MACVTAP], [
  LIBVIRT_RESULT_LIB([MACVTAP])
])
