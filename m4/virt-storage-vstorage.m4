dnl The storage vstorage check
dnl
dnl Copyright (C) 2016  Parallels IP Holdings GmbH, Inc.
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


AC_DEFUN([LIBVIRT_STORAGE_ARG_VSTORAGE], [
  LIBVIRT_ARG_WITH_FEATURE([STORAGE_VSTORAGE],
                           [Virtuozzo Storage backend for the storage driver],
                           [check])
])

AC_DEFUN([LIBVIRT_STORAGE_CHECK_VSTORAGE], [
  if test "$with_storage_vstorage" = "yes" ||
     test "$with_storage_vstorage" = "check"; then
    AC_PATH_PROG([VSTORAGE], [vstorage], [], [$LIBVIRT_SBIN_PATH])
    AC_PATH_PROG([VSTORAGE_MOUNT], [vstorage-mount], [], [$LIBVIRT_SBIN_PATH])
    AC_PATH_PROG([UMOUNT], [umount], [], [$LIBVIRT_SBIN_PATH])

    if test "$with_storage_vstorage" = "yes"; then
      if test -z "$VSTORAGE" || test -z "$VSTORAGE_MOUNT"; then
        AC_MSG_ERROR([We need vstorage and vstorage-mount tool for Vstorage storage driver]);
      fi
      if test -z "$UMOUNT" ; then
        AC_MSG_ERROR([We need umount for Vstorage storage driver]);
      fi
    else
      if test -z "$VSTORAGE" ; then
        with_storage_vstorage=no
      fi
      if test -z "$VSTORAGE_MOUNT" ; then
        with_storage_vstorage=no
      fi
      if test -z "$UMOUNT" ; then
        with_storage_vstorage=no
      fi

      if test "$with_storage_fs" = "check" ; then
        with_storage_vstorage=yes
      fi
    fi

    if test "$with_storage_vstorage" = "yes" ; then
      AC_DEFINE_UNQUOTED([WITH_STORAGE_VSTORAGE], 1,
                         [whether Vstorage backend for storage driver is enabled])
      AC_DEFINE_UNQUOTED([VSTORAGE], ["$VSTORAGE"],
                         [Location or name of the vstorage client tool])
      AC_DEFINE_UNQUOTED([VSTORAGE_MOUNT], ["$VSTORAGE_MOUNT"],
                         [Location or name of the vstorage mount tool])
      AC_DEFINE_UNQUOTED([UMOUNT], ["$UMOUNT"],
                         [Location or name of the umount programm])
    fi
  fi
  AM_CONDITIONAL([WITH_STORAGE_VSTORAGE], [test "$with_storage_vstorage" = "yes"])
])

AC_DEFUN([LIBVIRT_STORAGE_RESULT_VSTORAGE], [
  LIBVIRT_RESULT([Virtuozzo storage], [$with_storage_vstorage])
])
