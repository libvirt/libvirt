dnl The XenAPI driver
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

AC_DEFUN([LIBVIRT_DRIVER_ARG_XENAPI], [
  LIBVIRT_ARG_WITH_FEATURE([XENAPI], [XenAPI], [check])
])

AC_DEFUN([LIBVIRT_DRIVER_CHECK_XENAPI], [
  AC_REQUIRE([LIBVIRT_CHECK_CURL])

  old_with_xenapi="$with_xenapi"

  dnl search for the XenServer library
  LIBVIRT_CHECK_LIB([XENAPI], [xenserver], [xen_vm_start], [xen/api/xen_vm.h])

  if test "x$with_xenapi" = "xyes" ; then
    if test "x$with_curl" = "xno"; then
      if test "$old_with_xenapi" != "check"; then
        AC_MSG_ERROR([You must install libcurl to compile the XenAPI driver])
      fi
      with_xenapi=no
    fi
  fi
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_XENAPI], [
  LIBVIRT_RESULT([XenAPI], [$with_xenapi])
])

AC_DEFUN([LIBVIRT_RESULT_XENAPI], [
  LIBVIRT_RESULT_LIB([XENAPI])
])
