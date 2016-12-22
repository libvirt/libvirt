dnl The VMware driver check
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

AC_DEFUN([LIBVIRT_DRIVER_ARG_VMWARE], [
  LIBVIRT_ARG_WITH_FEATURE([VMWARE], [VMware], [yes])
])

AC_DEFUN([LIBVIRT_DRIVER_CHECK_VMWARE], [
  if test "$with_vmware" = "yes"; then
    AC_DEFINE_UNQUOTED([WITH_VMWARE], 1, [whether VMware driver is enabled])
  fi
  AM_CONDITIONAL([WITH_VMWARE], [test "$with_vmware" = "yes"])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_VMWARE], [
  LIBVIRT_RESULT([VMware], [$with_vmware])
])
