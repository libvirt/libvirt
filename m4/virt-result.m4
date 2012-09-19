dnl
dnl virt-result.m4: Helper macros for checking for libraries
dnl
dnl Copyright (C) 2012-2013 Red Hat, Inc.
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

dnl
dnl To be used to print the results of a conditional test
dnl
dnl  LIBVIRT_RESULT(CHECK_NAME, STATUS, DETAILS)
dnl
dnl    CHECK_NAME: Name of the item being checked
dnl        STATUS: 'yes' or 'no' result of check
dnl       DETAILS: Details of result eg compiler flags
dnl
dnl  eg
dnl
dnl  LIBVIRT_RESULT([yajl], [yes], [-I/opt/yajl/include -lyajl])
dnl
AC_DEFUN([LIBVIRT_RESULT], [
  if test "$2" = "no" || test -z "$3" ; then
    STR=`printf "%10s: %-3s" "$1" "$2"`
  else
    STR=`printf "%10s: %-3s (%s)" "$1" "$2" "$3"`
  fi

  AC_MSG_NOTICE([$STR])
])
