dnl The storage dir check
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

AC_DEFUN([LIBVIRT_STORAGE_ARG_DIR], [
  LIBVIRT_ARG_WITH_FEATURE([STORAGE_DIR], [directory backend for the storage driver], [yes])
])

AC_DEFUN([LIBVIRT_STORAGE_CHECK_DIR], [
  if test "$with_storage_dir" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_STORAGE_DIR], 1, [whether directory backend for storage driver is enabled])
  fi
  AM_CONDITIONAL([WITH_STORAGE_DIR], [test "$with_storage_dir" = "yes"])
])

AC_DEFUN([LIBVIRT_STORAGE_RESULT_DIR], [
  LIBVIRT_RESULT([Dir], [$with_storage_dir])
])
