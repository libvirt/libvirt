dnl The loader:nvram list check
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

AC_DEFUN([LIBVIRT_ARG_LOADER_NVRAM], [
  LIBVIRT_ARG_WITH([LOADER_NVRAM],
                   [Pass list of pairs of <loader>:<nvram> paths.
                    Both pairs and list items are separated by a colon.],
                   [''])
])

AC_DEFUN([LIBVIRT_CHECK_LOADER_NVRAM], [
  if test "x$with_loader_nvram" != "xno" && \
     test "x$with_loader_nvram" != "x" ; then
    l=$(echo $with_loader_nvram | tr ':' '\n' | wc -l)
    if test $(expr $l % 2) -ne 0 ; then
      AC_MSG_ERROR([Malformed --with-loader-nvram argument])
    elif test $l -gt 0 ; then
      AC_MSG_WARN([Note that --with-loader-nvram is obsolete and will be removed soon])
    fi
    AC_DEFINE_UNQUOTED([DEFAULT_LOADER_NVRAM], ["$with_loader_nvram"],
                       [List of loader:nvram pairs])
  fi
])

AC_DEFUN([LIBVIRT_RESULT_LOADER_NVRAM], [
  if test "x$with_loader_nvram" != "xno" && \
     test "x$with_loader_nvram" != "x" ; then
    LIBVIRT_RESULT([Loader/NVRAM], [$with_loader_nvram],
                   [!!! Using this configure option is strongly discouraged !!!])
  else
    LIBVIRT_RESULT([Loader/NVRAM], [$with_loader_nvram])
  fi
])
