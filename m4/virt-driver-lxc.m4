dnl The LXC driver
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

AC_DEFUN([LIBVIRT_DRIVER_ARG_LXC], [
  LIBVIRT_ARG_WITH_FEATURE([LXC], [Linux Container], [check])
])

AC_DEFUN([LIBVIRT_DRIVER_CHECK_LXC], [
  if test "$with_libvirtd" = "no" ; then
    with_lxc=no
  fi

  if test "$with_lxc" = "yes" || test "$with_lxc" = "check"; then
    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
        #include <sched.h>
        #include <linux/loop.h>
        #include <sys/epoll.h>
      ]], [[
        unshare(!(LO_FLAGS_AUTOCLEAR + EPOLL_CLOEXEC));
      ]])
    ], [
      with_lxc=yes
      AC_DEFINE([HAVE_DECL_LO_FLAGS_AUTOCLEAR], [1],
        [Define to 1 if you have the declaration of `LO_FLAGS_AUTOCLEAR',
         and to 0 if you don't.])
    ], [
      if test "$with_lxc" = "check"; then
        with_lxc=no
        AC_MSG_NOTICE([Required kernel features were not found, disabling LXC])
      else
        AC_MSG_ERROR([Required kernel features for LXC were not found])
      fi
    ])

    AC_LINK_IFELSE([
      AC_LANG_PROGRAM([[
        #include <sched.h>
        #include <linux/loop.h>
        #include <sys/epoll.h>
      ]], [[
        unshare(!(LOOP_CTL_GET_FREE));
      ]])
    ], [
      AC_DEFINE([HAVE_DECL_LOOP_CTL_GET_FREE], [1],
        [Define to 1 if you have the declaration of `LOOP_CTL_GET_FREE',
         and to 0 if you don't.])
    ])
  fi
  if test "$with_lxc" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_LXC], 1, [whether LXC driver is enabled])
  fi
  AM_CONDITIONAL([WITH_LXC], [test "$with_lxc" = "yes"])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_LXC], [
  LIBVIRT_RESULT([LXC], [$with_lxc])
])
