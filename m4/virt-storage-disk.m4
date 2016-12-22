dnl The storage disk check
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

AC_DEFUN([LIBVIRT_STORAGE_ARG_DISK], [
  LIBVIRT_ARG_WITH_FEATURE([STORAGE_DISK], [GPartd Disk backend for the storage driver],
                           [check])
])

AC_DEFUN([LIBVIRT_STORAGE_CHECK_DISK], [
  AC_REQUIRE([LIBVIRT_CHECK_DEVMAPPER])
  AC_REQUIRE([LIBVIRT_CHECK_LIBPARTED])

  if test "$with_storage_disk" = "yes" ||
     test "$with_storage_disk" = "check"; then

    if test "$with_storage_disk" = "yes" &&
       test "$with_libparted" != "yes"; then
      AC_MSG_ERROR([Need parted for disk storage driver])
    fi

    if test "$with_storage_disk" = "check"; then
      with_storage_disk="$with_libparted"
    fi

    if test "$with_storage_disk" = "yes"; then
      AC_DEFINE_UNQUOTED([WITH_STORAGE_DISK], 1,
                         [whether Disk backend for storage driver is enabled])
    fi
  fi

  if test "x$with_storage_disk" = "xyes"; then
    if test "x$with_devmapper" = "xno"; then
      AC_MSG_ERROR([You must install device-mapper-devel/libdevmapper to compile libvirt with disk storage driver])
    fi
  fi

  AM_CONDITIONAL([WITH_STORAGE_DISK], [test "$with_storage_disk" = "yes"])
])

AC_DEFUN([LIBVIRT_STORAGE_RESULT_DISK], [
  LIBVIRT_RESULT([Disk], [$with_storage_disk])
])
