dnl The UML driver
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

AC_DEFUN([LIBVIRT_DRIVER_CHECK_UML],[
    AC_ARG_WITH([uml],
      [AS_HELP_STRING([--with-uml],
        [add UML support @<:@default=check@:>@])])
    m4_divert_text([DEFAULTS], [with_uml=check])

    if test "$with_libvirtd" = "no" || test "$with_linux" = "no"; then
        if test "$with_uml" = "yes"; then
            AC_MSG_ERROR([The UML driver cannot be enabled])
        elif test "$with_uml" = "check"; then
            with_uml="no"
        fi
    fi

    if test "$with_uml" = "yes" || test "$with_uml" = "check"; then
        AC_CHECK_HEADER([sys/inotify.h], [
          with_uml=yes
        ], [
          if test "$with_uml" = "check"; then
              with_uml=no
              AC_MSG_NOTICE([<sys/inotify.h> is required for the UML driver, disabling it])
          else
              AC_MSG_ERROR([The <sys/inotify.h> is required for the UML driver. Upgrade your libc6.])
          fi
        ])
    fi

    if test "$with_uml" = "yes" ; then
        AC_DEFINE_UNQUOTED([WITH_UML], 1, [whether UML driver is enabled])
    fi
    AM_CONDITIONAL([WITH_UML], [test "$with_uml" = "yes"])
])

AC_DEFUN([LIBVIRT_DRIVER_RESULT_UML],[
    AC_MSG_NOTICE([      UML: $with_uml])
])
