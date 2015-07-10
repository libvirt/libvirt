dnl The Virtuozzo driver
dnl
dnl Copyright (C) 2005-2015 Red Hat, Inc.
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

AC_DEFUN([LIBVIRT_DRIVER_CHECK_VZ],[
    AC_ARG_WITH([vz],
      [AS_HELP_STRING([--with-vz],
        [add Virtuozzo support @<:@default=check@:>@])])
    m4_divert_text([DEFAULTS], [with_vz=check])

    if test "$with_vz" = "yes" ||
       test "$with_vz" = "check"; then
        PKG_CHECK_MODULES([PARALLELS_SDK], [parallels-sdk >= $PARALLELS_SDK_REQUIRED],
                          [PARALLELS_SDK_FOUND=yes], [PARALLELS_SDK_FOUND=no])

        if test "$with_vz" = "yes" && test "$PARALLELS_SDK_FOUND" = "no"; then
            AC_MSG_ERROR([Parallels Virtualization SDK is needed to build the Virtuozzo driver.])
        fi

        with_vz=$PARALLELS_SDK_FOUND
        if test "$with_vz" = "yes"; then
            AC_DEFINE_UNQUOTED([WITH_VZ], 1,
                               [whether vz driver is enabled])
        fi
    fi
    AM_CONDITIONAL([WITH_VZ], [test "$with_vz" = "yes"])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_VZ],[
    AC_MSG_NOTICE([       vz: $with_vz])
])
