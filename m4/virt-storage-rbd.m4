dnl The storage RBD check
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

AC_DEFUN([LIBVIRT_STORAGE_ARG_RBD], [
  LIBVIRT_ARG_WITH_FEATURE([STORAGE_RBD],
                           [RADOS Block Device backend for the storage driver], [check])
])

AC_DEFUN([LIBVIRT_STORAGE_CHECK_RBD], [
  LIBRBD_LIBS=
  if test "$with_storage_rbd" = "yes" || test "$with_storage_rbd" = "check"; then
    AC_CHECK_HEADER([rbd/librbd.h], [LIBRBD_FOUND=yes; break;])

    if test "$LIBRBD_FOUND" = "yes"; then
      with_storage_rbd=yes
      LIBRBD_LIBS="-lrbd -lrados"
      AC_DEFINE_UNQUOTED([WITH_STORAGE_RBD], [1],
                         [whether RBD backend for storage driver is enabled])
    else
      with_storage_rbd=no
    fi
  fi
  AM_CONDITIONAL([WITH_STORAGE_RBD], [test "$with_storage_rbd" = "yes"])
  AC_SUBST([LIBRBD_LIBS])
])

AC_DEFUN([LIBVIRT_STORAGE_RESULT_RBD], [
  LIBVIRT_RESULT([RBD], [$with_storage_rbd])
])

AC_DEFUN([LIBVIRT_RESULT_RBD], [
  LIBVIRT_RESULT([rbd], [$with_storage_rbd], [CFLAGS='' LIBS='$LIBRBD_LIBS'])
])
