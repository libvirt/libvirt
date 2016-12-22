dnl The storage iSCSI check
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

AC_DEFUN([LIBVIRT_STORAGE_ARG_ISCSI], [
  LIBVIRT_ARG_WITH_FEATURE([STORAGE_ISCSI], [iSCSI backend for the storage driver],
                           [check])
])

AC_DEFUN([LIBVIRT_STORAGE_CHECK_ISCSI], [
  if test "$with_storage_iscsi" = "yes" || test "$with_storage_iscsi" = "check"; then
    AC_PATH_PROG([ISCSIADM], [iscsiadm], [], [$LIBVIRT_SBIN_PATH])
    if test "$with_storage_iscsi" = "yes" ; then
      if test -z "$ISCSIADM" ; then AC_MSG_ERROR([We need iscsiadm for iSCSI storage driver]) ; fi
    else
      if test -z "$ISCSIADM" ; then with_storage_iscsi=no ; fi

      if test "$with_storage_iscsi" = "check" ; then with_storage_iscsi=yes ; fi
    fi

    if test "$with_storage_iscsi" = "yes" ; then
      AC_DEFINE_UNQUOTED([WITH_STORAGE_ISCSI], 1, [whether iSCSI backend for storage driver is enabled])
    fi
  fi
  if test -z "$ISCIADM" ; then
    AC_DEFINE_UNQUOTED([ISCSIADM],["iscsiadm"],[Name of iscsiadm program])
  else
    AC_DEFINE_UNQUOTED([ISCSIADM],["$ISCSIADM"],[Location of iscsiadm program])
  fi
  AM_CONDITIONAL([WITH_STORAGE_ISCSI], [test "$with_storage_iscsi" = "yes"])
])

AC_DEFUN([LIBVIRT_STORAGE_RESULT_ISCSI], [
  LIBVIRT_RESULT([iSCSI], [$with_storage_iscsi])
])
