dnl The storage ZFS check
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

AC_DEFUN([LIBVIRT_STORAGE_ARG_ZFS], [
  LIBVIRT_ARG_WITH_FEATURE([STORAGE_ZFS], [ZFS backend for the storage driver], [check])
])

AC_DEFUN([LIBVIRT_STORAGE_CHECK_ZFS], [
  if test "$with_storage_zfs" = "yes" ||
     test "$with_storage_zfs" = "check"; then
    AC_PATH_PROG([ZFS], [zfs], [], [$LIBVIRT_SBIN_PATH])
    AC_PATH_PROG([ZPOOL], [zpool], [], [$LIBVIRT_SBIN_PATH])

    if test "$with_storage_zfs" = "yes"; then
      if test -z "$ZFS" || test -z "$ZPOOL"; then
        AC_MSG_ERROR([We need zfs and zpool for ZFS storage driver])
      fi
    else
      if test -z "$ZFS" || test -z "$ZPOOL"; then
        with_storage_zfs=no
      fi

      if test "$with_storage_zfs" = "check"; then
        with_storage_zfs=yes
      fi
    fi

    if test "$with_storage_zfs" = "yes"; then
      AC_DEFINE_UNQUOTED([WITH_STORAGE_ZFS], 1,
        [whether ZFS backend for storage driver is enabled])
      AC_DEFINE_UNQUOTED([ZFS], ["$ZFS"], [Location of zfs program])
      AC_DEFINE_UNQUOTED([ZPOOL], ["$ZPOOL"], [Location of zpool program])
    fi
  fi
  AM_CONDITIONAL([WITH_STORAGE_ZFS], [test "$with_storage_zfs" = "yes"])
])

AC_DEFUN([LIBVIRT_STORAGE_RESULT_ZFS], [
  LIBVIRT_RESULT([ZFS], [$with_storage_zfs])
])
