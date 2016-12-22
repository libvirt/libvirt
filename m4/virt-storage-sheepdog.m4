dnl The storage Sheepdog check
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

AC_DEFUN([LIBVIRT_STORAGE_ARG_SHEEPDOG], [
  LIBVIRT_ARG_WITH_FEATURE([STORAGE_SHEEPDOG],
                           [with Sheepdog backend for the storage driver], [check])
])

AC_DEFUN([LIBVIRT_STORAGE_CHECK_SHEEPDOG], [
  if test "$with_storage_sheepdog" = "yes" ||
     test "$with_storage_sheepdog" = "check"; then
    AC_PATH_PROGS([SHEEPDOGCLI], [collie dog], [], [$LIBVIRT_SBIN_PATH])

    if test "$with_storage_sheepdog" = "yes"; then
      if test -z "$SHEEPDOGCLI"; then
        AC_MSG_ERROR([We need sheepdog client for Sheepdog storage driver])
      fi
    else
      if test -z "$SHEEPDOGCLI"; then
        with_storage_sheepdog=no
      fi

      if test "$with_storage_sheepdog" = "check"; then
        with_storage_sheepdog=yes
      fi
    fi

    if test "$with_storage_sheepdog" = "yes"; then
      AC_DEFINE_UNQUOTED([WITH_STORAGE_SHEEPDOG], 1,
                         [whether Sheepdog backend for storage driver is enabled])
      AC_DEFINE_UNQUOTED([SHEEPDOGCLI], ["$SHEEPDOGCLI"],
                         [Location of sheepdog client program])
    fi
  fi
  AM_CONDITIONAL([WITH_STORAGE_SHEEPDOG], [test "$with_storage_sheepdog" = "yes"])
])

AC_DEFUN([LIBVIRT_STORAGE_RESULT_SHEEPDOG], [
  LIBVIRT_RESULT([Sheepdog], [$with_storage_sheepdog])
])
