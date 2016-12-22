dnl The Phyp driver
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

AC_DEFUN([LIBVIRT_DRIVER_ARG_PHYP], [
  LIBVIRT_ARG_WITH_FEATURE([PHYP], [PHYP], [check])
])

AC_DEFUN([LIBVIRT_DRIVER_CHECK_PHYP], [
  AC_REQUIRE([LIBVIRT_CHECK_SSH2])

  if test "$with_phyp" != "no"; then
    if test "$with_ssh2" = "no" ; then
      if test "$with_phyp" = "check"; then
        with_phyp=no
      else
        AC_MSG_ERROR([libssh2 is required for Phyp driver])
      fi
    else
      with_phyp=yes
    fi
  fi

  if test "$with_phyp" = "yes"; then
    AC_DEFINE_UNQUOTED([WITH_PHYP], 1, [whether IBM HMC / IVM driver is enabled])
  fi

  AM_CONDITIONAL([WITH_PHYP],[test "$with_phyp" = "yes"])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_PHYP], [
  LIBVIRT_RESULT([PHYP], [$with_phyp])
])
