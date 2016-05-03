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

AC_DEFUN([LIBVIRT_CHECK_INIT_SCRIPT],[
    AC_ARG_WITH([init-script],
        [AS_HELP_STRING([--with-init-script@<:@=STYLE@:>@],
        [Style of init script to install: redhat, systemd, systemd+redhat,
         upstart, check, none @<:@default=check@:>@])],
        [],[with_init_script=check])

    AC_MSG_CHECKING([for init script type])

    init_redhat=no
    init_systemd=no
    init_upstart=no

    if test "$with_init_script" = check && test "$cross_compiling" = yes; then
        with_init_script=none
    fi
    if test "$with_init_script" = check && type systemctl >/dev/null 2>&1; then
        with_init_script=systemd
    fi
    if test "$with_init_script" = check && test -f /etc/redhat-release; then
        with_init_script=redhat
    fi
    if test "$with_init_script" = check; then
        with_init_script=none
    fi

    AS_CASE([$with_init_script],
        [systemd+redhat],[
            init_redhat=yes
            init_systemd=yes
        ],
        [systemd],[
            init_systemd=yes
        ],
        [upstart],[
            init_upstart=yes
        ],
        [redhat],[
            init_redhat=yes
        ],
        [none],[],
        [*],[
            AC_MSG_ERROR([Unknown initscript flavour $with_init_script])
        ]
    )

    AM_CONDITIONAL([LIBVIRT_INIT_SCRIPT_RED_HAT], test "$init_redhat" = "yes")
    AM_CONDITIONAL([LIBVIRT_INIT_SCRIPT_UPSTART], test "$init_upstart" = "yes")
    AM_CONDITIONAL([LIBVIRT_INIT_SCRIPT_SYSTEMD], test "$init_systemd" = "yes")

    AC_MSG_RESULT($with_init_script)
])

AC_DEFUN([LIBVIRT_RESULT_INIT_SCRIPT],[
    AC_MSG_NOTICE([       Init script: $with_init_script])
])
