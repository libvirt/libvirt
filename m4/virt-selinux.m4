dnl The libselinux.so library
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

AC_DEFUN([LIBVIRT_CHECK_SELINUX],[
  LIBVIRT_CHECK_LIB([SELINUX], [selinux],
                    [fgetfilecon_raw], [selinux/selinux.h])

  AC_ARG_WITH([selinux_mount],
    [AS_HELP_STRING([--with-selinux-mount],
      [set SELinux mount point @<:@default=check@:>@])],
    [],
    [with_selinux_mount=check])

  if test "$with_selinux" = "yes"; then
    # libselinux changed signatures between 2.2 and 2.3
    AC_CACHE_CHECK([for selinux setcon parameter type], [lv_cv_setcon_const],
    [AC_COMPILE_IFELSE(
      [AC_LANG_PROGRAM(
         [[
#include <selinux/selinux.h>
int setcon(char *context);
         ]])],
         [lv_cv_setcon_const=''],
         [lv_cv_setcon_const='const'])])
    AC_DEFINE_UNQUOTED([VIR_SELINUX_CTX_CONST], [$lv_cv_setcon_const],
      [Define to empty or 'const' depending on how SELinux qualifies its
       security context parameters])

    AC_MSG_CHECKING([SELinux mount point])
    if test "$with_selinux_mount" = "check" || test -z "$with_selinux_mount"; then
      if test -d /sys/fs/selinux ; then
        SELINUX_MOUNT=/sys/fs/selinux
      else
        SELINUX_MOUNT=/selinux
      fi
    else
      SELINUX_MOUNT=$with_selinux_mount
    fi
    AC_MSG_RESULT([$SELINUX_MOUNT])
    AC_DEFINE_UNQUOTED([SELINUX_MOUNT], ["$SELINUX_MOUNT"], [SELinux mount point])

    dnl We prefer to use <selinux/label.h> and selabel_open, but can fall
    dnl back to matchpathcon for the sake of RHEL 5's version of libselinux.
    AC_CHECK_HEADERS([selinux/label.h])
  fi
])

AC_DEFUN([LIBVIRT_RESULT_SELINUX],[
  LIBVIRT_RESULT_LIB([SELINUX])
])
