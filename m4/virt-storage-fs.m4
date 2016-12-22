dnl The storage fs check
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

AC_DEFUN([LIBVIRT_STORAGE_ARG_FS], [
  LIBVIRT_ARG_WITH_FEATURE([STORAGE_FS], [FileSystem backend for the storage driver],
                           [check])
])

AC_DEFUN([LIBVIRT_STORAGE_CHECK_FS], [
  if test "$with_storage_fs" = "yes" || test "$with_storage_fs" = "check"; then
    AC_CHECK_HEADER([mntent.h], , [
      if test "$with_storage_fs" = "check"; then
        with_storage_fs=no
        AC_MSG_NOTICE([<mntent.h> is required for the FS storage driver, disabling it])
      else
        AC_MSG_ERROR([<mntent.h> is required for the FS storage driver])
      fi
    ])
  fi

  if test "$with_storage_fs" = "yes" || test "$with_storage_fs" = "check"; then
    AC_PATH_PROG([MOUNT], [mount], [], [$LIBVIRT_SBIN_PATH])
    AC_PATH_PROG([UMOUNT], [umount], [], [$LIBVIRT_SBIN_PATH])
    AC_PATH_PROG([MKFS], [mkfs], [], [$LIBVIRT_SBIN_PATH])
    if test "$with_storage_fs" = "yes" ; then
      if test -z "$MOUNT" ; then
        AC_MSG_ERROR([We need mount for FS storage driver])
      fi
      if test -z "$UMOUNT" ; then
        AC_MSG_ERROR([We need umount for FS storage driver])
      fi
      if test -z "$MKFS" ; then
        AC_MSG_ERROR([We need mkfs for FS storage driver])
      fi
    else
      if test -z "$MOUNT" ; then
        with_storage_fs=no
      fi
      if test -z "$UMOUNT" ; then
        with_storage_fs=no
      fi
      if test -z "$MKFS" ; then
        with_storage_fs=no
      fi

      if test "$with_storage_fs" = "check" ; then
        with_storage_fs=yes
      fi
    fi

    if test "$with_storage_fs" = "yes" ; then
      AC_DEFINE_UNQUOTED([WITH_STORAGE_FS], 1,
                         [whether FS backend for storage driver is enabled])
      AC_DEFINE_UNQUOTED([MOUNT], ["$MOUNT"],
                         [Location or name of the mount program])
      AC_DEFINE_UNQUOTED([UMOUNT], ["$UMOUNT"],
                         [Location or name of the mount program])
      AC_DEFINE_UNQUOTED([MKFS], ["$MKFS"],
                         [Location or name of the mkfs program])
    fi
  fi
  AM_CONDITIONAL([WITH_STORAGE_FS], [test "$with_storage_fs" = "yes"])
  if test "$with_storage_fs" = "yes"; then
    AC_PATH_PROG([SHOWMOUNT], [showmount], [], [$LIBVIRT_SBIN_PATH])
    AC_DEFINE_UNQUOTED([SHOWMOUNT], ["$SHOWMOUNT"],
                       [Location or name of the showmount program])
  fi
])

AC_DEFUN([LIBVIRT_STORAGE_RESULT_FS], [
  LIBVIRT_RESULT([FS], [$with_storage_fs])
  LIBVIRT_RESULT([NetFS], [$with_storage_fs])
])
