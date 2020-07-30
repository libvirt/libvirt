dnl The libselinux.so library
dnl
dnl Copyright (C) 2012-2014, 2016 Red Hat, Inc.
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

AC_DEFUN([LIBVIRT_ARG_SELINUX],[
  LIBVIRT_ARG_WITH_FEATURE([SELINUX], [SELinux], [check])
  LIBVIRT_ARG_WITH([SELINUX_MOUNT], [set SELinux mount point], [check])
])

AC_DEFUN([LIBVIRT_CHECK_SELINUX],[
  LIBVIRT_CHECK_LIB([SELINUX], [selinux],
                    [fgetfilecon_raw], [selinux/selinux.h])

  if test "$with_selinux" = "yes"; then
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
  fi
])

AC_DEFUN([LIBVIRT_RESULT_SELINUX],[
  LIBVIRT_RESULT_LIB([SELINUX])
])
