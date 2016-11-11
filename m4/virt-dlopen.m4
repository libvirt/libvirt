dnl The dlopen library
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

AC_DEFUN([LIBVIRT_CHECK_DLOPEN], [

  with_dlopen=yes
  with_dlfcn=yes

  AC_CHECK_HEADER([dlfcn.h],, [with_dlfcn=no])
  AC_SEARCH_LIBS([dlopen], [dl],, [with_dlopen=no])

  case $ac_cv_search_dlopen:$host_os in
    'none required'* | *:mingw* | *:msvc*)
      DLOPEN_LIBS= ;;
    no*)
      AC_MSG_ERROR([Unable to find dlopen()]) ;;
    *)
      if test "x$with_dlfcn" != "xyes"; then
        AC_MSG_ERROR([Unable to find dlfcn.h])
      fi
      DLOPEN_LIBS=$ac_cv_search_dlopen ;;
  esac

  AC_SUBST([DLOPEN_LIBS])
])

AC_DEFUN([LIBVIRT_RESULT_DLOPEN], [
  LIBVIRT_RESULT_LIB([DLOPEN])
])
