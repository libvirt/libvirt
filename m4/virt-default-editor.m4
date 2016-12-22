dnl The default editor check
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

AC_DEFUN([LIBVIRT_ARG_DEFAULT_EDITOR], [
  LIBVIRT_ARG_WITH([DEFAULT_EDITOR],
                   [Editor to use for interactive commands], [vi])
])

AC_DEFUN([LIBVIRT_CHECK_DEFAULT_EDITOR], [
  AC_DEFINE_UNQUOTED([DEFAULT_EDITOR], ["$with_default_editor"],
                     [Default editor to use])
])

AC_DEFUN([LIBVIRT_RESULT_DEFAULT_EDITOR], [
  AC_MSG_NOTICE([    Default Editor: $with_default_editor])
])
