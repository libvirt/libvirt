dnl The storage mpath check
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

AC_DEFUN([LIBVIRT_STORAGE_ARG_MPATH], [
  LIBVIRT_ARG_WITH_FEATURE([STORAGE_MPATH], [mpath backend for the storage driver],
                           [check])
])

AC_DEFUN([LIBVIRT_STORAGE_CHECK_MPATH], [
  AC_REQUIRE([LIBVIRT_CHECK_DEVMAPPER])

  if test "$with_storage_mpath" = "check" || test "$with_storage_mpath" = "yes"; then
    if test "$with_linux" = "yes"; then
      with_storage_mpath=yes

      AC_DEFINE_UNQUOTED([WITH_STORAGE_MPATH], 1,
        [whether mpath backend for storage driver is enabled])
    else
      if test "$with_storage_mpath" = "yes"; then
        AC_MSG_ERROR([mpath storage is only supported on Linux])
      fi
      with_storage_mpath=no
    fi
  fi

  if test "x$with_storage_mpath" = "xyes"; then
    if test "x$with_devmapper" = "xno"; then
      AC_MSG_ERROR([You must install device-mapper-devel/libdevmapper to compile libvirt with mpath storage driver])
    fi
  fi

  AM_CONDITIONAL([WITH_STORAGE_MPATH], [test "$with_storage_mpath" = "yes"])
])

AC_DEFUN([LIBVIRT_STORAGE_RESULT_MPATH], [
  LIBVIRT_RESULT([mpath], [$with_storage_mpath])
])
