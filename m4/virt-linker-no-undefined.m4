dnl
dnl Check for -z defs linker flag
dnl
dnl Copyright (C) 2013-2018 Red Hat, Inc.
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

AC_DEFUN([LIBVIRT_LINKER_NO_UNDEFINED],[
    AC_MSG_CHECKING([for how to stop undefined symbols at link time])

    NO_UNDEFINED_LDFLAGS=
    ld_help=`$LD --help 2>&1`
    case $ld_help in
        *"-z defs"*) NO_UNDEFINED_LDFLAGS="-Wl,-z -Wl,defs" ;;
    esac
    AC_SUBST([NO_UNDEFINED_LDFLAGS])

    AC_MSG_RESULT([$NO_UNDEFINED_LDFLAGS])
])
