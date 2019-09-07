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

m4_defun_init([_AS_ECHO_LOG_N],
[AS_REQUIRE([_AS_LINENO_PREPARE])],
[_AS_ECHO_N([$as_me:${as_lineno-$LINENO}: $1], AS_MESSAGE_LOG_FD)])

m4_defun_init([AS_MESSAGE_N],
[AS_REQUIRE([_AS_ME_PREPARE])],
[m4_ifval(AS_MESSAGE_LOG_FD,
	  [{ _AS_ECHO_LOG_N([$1])
_AS_ECHO_N([$as_me: $1], [$2]);}],
	  [_AS_ECHO_N([$as_me: $1], [$2])])[]])

AC_DEFUN([LIBVIRT_RESULT], [
  STR=`printf "%20s: " "$1"`
  if test "$2" = "no" || test -z "$3" ; then
    VAL=`printf "%s" "$2"`
  else
    VAL=`printf "%s (%s)" "$2" "$3"`
  fi

  AS_MESSAGE_N([$STR])
  _AS_ECHO([$VAL], AS_MESSAGE_LOG_FD)
  COLORIZE_RESULT([$VAL])
])
