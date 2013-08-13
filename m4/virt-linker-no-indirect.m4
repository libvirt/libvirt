dnl
dnl Check for --no-copy-dt-needed-entries
dnl
dnl Copyright (C) 2013 Guido Günther <agx@sigxcpu.org>
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

AC_DEFUN([LIBVIRT_LINKER_NO_INDIRECT],[
    AC_MSG_CHECKING([for how to avoid indirect lib deps])

    NO_INDIRECT_LDFLAGS=
    case `$LD --help 2>&1` in
        *"--no-copy-dt-needed-entries"*)
		NO_INDIRECT_LDFLAGS="-Wl,--no-copy-dt-needed-entries" ;;
    esac
    AC_SUBST([NO_INDIRECT_LDFLAGS])

    AC_MSG_RESULT([$NO_INDIRECT_LDFLAGS])
])
