dnl The ESX driver
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

AC_DEFUN([LIBVIRT_DRIVER_ARG_ESX], [
  LIBVIRT_ARG_WITH_FEATURE([ESX], [ESX], [check])
])

AC_DEFUN([LIBVIRT_DRIVER_CHECK_ESX], [
  AC_REQUIRE([LIBVIRT_CHECK_CURL])
  AC_REQUIRE([LIBVIRT_DRIVER_CHECK_VMWARE])

  if test "$with_curl" != "yes" ; then
    if test "$with_esx" != "yes"; then
      with_esx=no
    else
      AC_MSG_ERROR([Curl is required for the ESX driver])
    fi
  else
    if test "$with_esx" = "check"; then
      with_esx=yes
    fi
  fi

  if test "$with_esx" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_ESX], 1, [whether ESX driver is enabled])
  fi
  AM_CONDITIONAL([WITH_ESX], [test "$with_esx" = "yes"])

  with_vmx=yes
  if test "$with_esx" != "yes" && test "$with_vmware" != "yes"; then
    with_vmx=no
  fi
  if test "$with_vmx" = "yes" ; then
    AC_DEFINE_UNQUOTED([WITH_VMX], 1, [whether VMware VMX config handling is enabled])
  fi
  AM_CONDITIONAL([WITH_VMX], [test "$with_vmx" = "yes"])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_ESX], [
  LIBVIRT_RESULT([ESX], [$with_esx])
])
