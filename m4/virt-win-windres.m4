dnl The MinGW windres checks
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

AC_DEFUN([LIBVIRT_WIN_CHECK_WINDRES], [
  dnl Look for windres to build a Windows icon resource.
  with_windres=no
  case "$host" in
    *-*-mingw* )
      AC_CHECK_TOOL([WINDRES], [windres], [])
      if test "x$WINDRES" != "x"; then
        with_windres=yes
      fi
      ;;
  esac
  AM_CONDITIONAL([WITH_WIN_ICON], [test "$with_windres" = "yes"])
])

AC_DEFUN([LIBVIRT_WIN_RESULT_WINDRES], [
  LIBVIRT_RESULT([windres], [$with_windres], [$WINDRES])
])
