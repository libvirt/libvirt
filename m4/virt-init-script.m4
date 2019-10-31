dnl Init script type
dnl
dnl Copyright (C) 2005-2016 Red Hat, Inc.
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

AC_DEFUN([LIBVIRT_ARG_INIT_SCRIPT],[
    LIBVIRT_ARG_WITH([INIT_SCRIPT],
                     [Style of init script to install: systemd, openrc, check, none],
                     [check])
])

AC_DEFUN([LIBVIRT_CHECK_INIT_SCRIPT],[
    AC_MSG_CHECKING([for init script type])

    if test "$with_init_script" = check && test "$cross_compiling" = yes; then
        with_init_script=none
    fi
    if test "$with_init_script" = check && type systemctl >/dev/null 2>&1; then
        with_init_script=systemd
    fi
    if test "$with_init_script" = check && type openrc >/dev/null 2>&1; then
        with_init_script=openrc
    fi
    if test "$with_init_script" = check; then
        with_init_script=none
    fi

    AS_CASE([$with_init_script],
        [systemd],[],
        [openrc],[],
        [none],[],
        [*],[
            AC_MSG_ERROR([Unknown initscript flavour $with_init_script])
        ]
    )

    AM_CONDITIONAL([LIBVIRT_INIT_SCRIPT_SYSTEMD],
                   [test "$with_init_script" = "systemd"])
    AM_CONDITIONAL([LIBVIRT_INIT_SCRIPT_OPENRC],
                   [test "$with_init_script" = "openrc"])

    AC_MSG_RESULT($with_init_script)
])

AC_DEFUN([LIBVIRT_RESULT_INIT_SCRIPT],[
    LIBVIRT_RESULT([Init script], [$with_init_script])
])
