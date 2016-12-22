dnl The VirtualBox driver
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

AC_DEFUN([LIBVIRT_DRIVER_ARG_VBOX], [
  LIBVIRT_ARG_WITH_FEATURE([VBOX], [VirtualBox XPCOMC], [yes])
])

AC_DEFUN([LIBVIRT_DRIVER_CHECK_VBOX], [
  vbox_xpcomc_dir=

  if test "x$with_vbox" != "xyes" && test "x$with_vbox" != "xno"; then
    # intentionally don't do any further checks here on the provided path
    vbox_xpcomc_dir=$with_vbox
    with_vbox=yes
  fi

  AC_DEFINE_UNQUOTED([VBOX_XPCOMC_DIR], ["$vbox_xpcomc_dir"],
                     [Location of directory containing VirtualBox XPCOMC library])

  if test "x$with_vbox" = "xyes"; then
    AC_DEFINE_UNQUOTED([WITH_VBOX], 1, [whether VirtualBox driver is enabled])
  fi
  AM_CONDITIONAL([WITH_VBOX], [test "$with_vbox" = "yes"])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_VBOX], [
  LIBVIRT_RESULT([VBox], [$with_vbox])
])
