dnl The parted check
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

AC_DEFUN([LIBVIRT_CHECK_LIBPARTED], [
  PARTED_REQUIRED="1.8.0"

  with_libparted=check

  LIBVIRT_CHECK_PKG([LIBPARTED], [libparted], [$PARTED_REQUIRED])

  if test "x$with_libparted" = "xyes"; then
    AC_PATH_PROG([PARTED], [parted], [], [$LIBVIRT_SBIN_PATH])
    if test -z "$PARTED" ; then
      with_libparted=no
    fi
  fi

  if test "x$with_libparted" = "xyes"; then
    AC_DEFINE_UNQUOTED([PARTED], ["$PARTED"],
                       [Location or name of the parted program])
  fi
])
