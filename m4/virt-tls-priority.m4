dnl The TLS priority check
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

AC_DEFUN([LIBVIRT_ARG_TLS_PRIORITY], [
  LIBVIRT_ARG_WITH([TLS_PRIORITY],
                   [set the default TLS session priority string],
                   [NORMAL])
])

AC_DEFUN([LIBVIRT_CHECK_TLS_PRIORITY], [
  AC_DEFINE_UNQUOTED([TLS_PRIORITY], ["$with_tls_priority"],
                     [TLS default priority string])
])

AC_DEFUN([LIBVIRT_RESULT_TLS_PRIORITY], [
  LIBVIRT_RESULT([      TLS priority], [$with_tls_priority])
])
