dnl The MinGW common checks
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

AC_DEFUN([LIBVIRT_WIN_CHECK_COMMON], [
  WIN32_EXTRA_CFLAGS=
  WIN32_EXTRA_LIBS=

  case "$host" in
    *-*-mingw* )
      WIN32_EXTRA_LIBS="-lole32 -loleaut32"
      # If the host is Windows, and shared libraries are disabled, we
      # need to add -DLIBVIRT_STATIC to the CFLAGS for proper linking
      if test "x$enable_shared" = "xno"; then
        WIN32_EXTRA_CFLAGS="-DLIBVIRT_STATIC"
      fi
      ;;
  esac

  AC_SUBST([WIN32_EXTRA_CFLAGS])
  AC_SUBST([WIN32_EXTRA_LIBS])
])

AC_DEFUN([LIBVIRT_WIN_RESULT_COMMON], [
  details="CFLAGS='$WIN32_EXTRA_CFLAGS' LIBS='$WIN32_EXTRA_LIBS'"
  LIBVIRT_RESULT([MinGW], [$with_win], [$details])
])
