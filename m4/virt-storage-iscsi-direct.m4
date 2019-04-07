dnl Iscsi-direct storage
dnl
dnl Copyright (C) 2018 Clementine Hayat.
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

AC_DEFUN([LIBVIRT_STORAGE_ARG_ISCSI_DIRECT], [
  LIBVIRT_ARG_WITH_FEATURE([STORAGE_ISCSI_DIRECT],
                           [iscsi-direct backend for the storage driver],
                           [check])
])

AC_DEFUN([LIBVIRT_STORAGE_CHECK_ISCSI_DIRECT], [
  AC_REQUIRE([LIBVIRT_CHECK_LIBISCSI])
  if test "$with_storage_iscsi_direct" = "check"; then
    with_storage_iscsi_direct=$with_libiscsi
  fi
  if test "$with_storage_iscsi_direct" = "yes"; then
    if test "$with_libiscsi" = "no"; then
      AC_MSG_ERROR([Need libiscsi for iscsi-direct storage driver])
    fi
    AC_DEFINE_UNQUOTED([WITH_STORAGE_ISCSI_DIRECT], [1],
                       [whether iSCSI backend for storage driver is enabled])
  fi
  AM_CONDITIONAL([WITH_STORAGE_ISCSI_DIRECT],
                 [test "$with_storage_iscsi_direct" = "yes"])
])

AC_DEFUN([LIBVIRT_STORAGE_RESULT_ISCSI_DIRECT], [
  LIBVIRT_RESULT([iscsi-direct], [$with_storage_iscsi_direct])
])
