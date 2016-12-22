dnl The virtualport support check
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

AC_DEFUN([LIBVIRT_ARG_VIRTUALPORT], [
  LIBVIRT_ARG_WITH([VIRTUALPORT], [enable virtual port support], [check])
])

AC_DEFUN([LIBVIRT_CHECK_VIRTUALPORT],[
  AC_REQUIRE([LIBVIRT_CHECK_MACVTAP])

  dnl Warn the user and error out if they requested virtualport support
  dnl with configure options, but the required macvtap support isn't available

  if test "$with_virtualport" = "yes"; then
    if test "$with_macvtap" = "no"; then
      AC_MSG_ERROR([--with-virtualport requires --with-macvtap])
    fi
  fi

  dnl virtualport checks

  if test "$with_macvtap" != "yes"; then
    with_virtualport=no
  fi
  if test "$with_virtualport" != "no"; then
    AC_MSG_CHECKING([whether to compile with virtual port support])
    AC_TRY_COMPILE([ #include <sys/socket.h>
                     #include <linux/rtnetlink.h> ],
                     [ int x = IFLA_PORT_MAX; ],
                     [ with_virtualport=yes ],
                     [ if test "$with_virtualport" = "yes" ; then
                       AC_MSG_ERROR([Installed linux headers don't show support for virtual port support.])
                       fi
                       with_virtualport=no ])
    if test "$with_virtualport" = "yes"; then
      val=1
    else
      val=0
    fi
    AC_DEFINE_UNQUOTED([WITH_VIRTUALPORT], $val,
                       [whether vsi vepa support is enabled])
    AC_MSG_RESULT([$with_virtualport])
  fi
  AM_CONDITIONAL([WITH_VIRTUALPORT], [test "$with_virtualport" = "yes"])
])

AC_DEFUN([LIBVIRT_RESULT_VIRTUALPORT],[
  LIBVIRT_RESULT_LIB([VIRTUALPORT])
])
