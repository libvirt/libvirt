dnl The libyajl.so library
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

AC_DEFUN([LIBVIRT_ARG_YAJL],[
  LIBVIRT_ARG_WITH_FEATURE([YAJL], [yajl], [check])
])

AC_DEFUN([LIBVIRT_CHECK_YAJL],[
  dnl YAJL JSON library http://lloyd.github.com/yajl/
  if test "$with_yajl" = yes; then
    AC_MSG_ERROR([Compilation with YAJL is no longer supported])
  fi
  with_yajl=no
])

AC_DEFUN([LIBVIRT_RESULT_YAJL],[
  LIBVIRT_RESULT_LIB([YAJL])
])
