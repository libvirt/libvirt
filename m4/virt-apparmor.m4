dnl The libapparmor.so library
dnl
dnl Copyright (C) 2012-2013 Red Hat, Inc.
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

AC_DEFUN([LIBVIRT_CHECK_APPARMOR],[
  LIBVIRT_CHECK_LIB([APPARMOR], [apparmor],
                    [aa_change_profile], [sys/apparmor.h])

  AC_ARG_WITH([apparmor_mount],
    [AS_HELP_STRING([--with-apparmor-mount],
                   [set AppArmor mount point @<:@default=check@:>@])],
    [],
    [with_apparmor_mount=check])

  if test "$with_apparmor" = "yes"; then
    AC_DEFINE_UNQUOTED([APPARMOR_DIR],
                       "/etc/apparmor.d",
                       [path to apparmor directory])
    AC_DEFINE_UNQUOTED([APPARMOR_PROFILES_PATH],
                       "/sys/kernel/security/apparmor/profiles",
                       [path to kernel profiles])
  fi
])

AC_DEFUN([LIBVIRT_RESULT_APPARMOR],[
  LIBVIRT_RESULT_LIB([APPARMOR])
])
