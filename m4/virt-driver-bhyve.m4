dnl The bhyve driver
dnl
dnl Copyright (C) 2014 Roman Bogorodskiy
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

AC_DEFUN([LIBVIRT_DRIVER_CHECK_BHYVE],[
    AC_ARG_WITH([bhyve],
      [AS_HELP_STRING([--with-bhyve],
        [add BHyVe support @<:@default=check@:>@])])
    m4_divert_text([DEFAULTS], [with_bhyve=check])

    if test "$with_bhyve" != "no"; then
        AC_PATH_PROG([BHYVE], [bhyve], [], [$PATH:/usr/sbin])
        AC_PATH_PROG([BHYVECTL], [bhyvectl], [], [$PATH:/usr/sbin])
        AC_PATH_PROG([BHYVELOAD], [bhyveload], [], [$PATH:/usr/sbin/])

        if test -z "$BHYVE" || test -z "$BHYVECTL" \
            test -z "$BHYVELOAD" || test "$with_freebsd" = "no"; then
            if test "$with_bhyve" = "check"; then
                with_bhyve="no"
            else
                AC_MSG_ERROR([The bhyve driver cannot be enabled])
            fi
        else
            with_bhyve="yes"
        fi
    fi

    if test "$with_bhyve" = "yes"; then
        AC_DEFINE_UNQUOTED([WITH_BHYVE], 1, [whether bhyve driver is enabled])
        AC_DEFINE_UNQUOTED([BHYVE], ["$BHYVE"],
                           [Location of the bhyve tool])
        AC_DEFINE_UNQUOTED([BHYVECTL], ["$BHYVECTL"],
                           [Location of the bhyvectl tool])
        AC_DEFINE_UNQUOTED([BHYVELOAD], ["$BHYVELOAD"],
                           [Location of the bhyveload tool])
    fi
    AM_CONDITIONAL([WITH_BHYVE], [test "$with_bhyve" = "yes"])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_BHYVE],[
    AC_MSG_NOTICE([    Bhyve: $with_bhyve])
])
