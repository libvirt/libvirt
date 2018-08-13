dnl The libvirt nsswitch plugin
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

AC_DEFUN([LIBVIRT_ARG_NSS],[
  LIBVIRT_ARG_WITH([NSS_PLUGIN],
                   [enable Name Service Switch plugin for resolving guest
                    IP addresses], [check])
])

AC_DEFUN([LIBVIRT_CHECK_NSS],[
  bsd_nss=no
  fail=0
  if test "x$with_nss_plugin" != "xno" ; then
    if test "x$with_yajl" != "xyes" ; then
      if test "x$with_nss_plugin" = "xyes" ; then
        AC_MSG_ERROR([Can't build nss plugin without yajl])
      else
        with_nss_plugin=no
      fi
    fi

    if test "x$with_network" != "xyes" ; then
      if test "x$with_nss_plugin" = "xyes" ; then
        AC_MSG_ERROR([Can't build nss plugin without network])
      else
        with_nss_plugin=no
      fi
    fi

    if test "x$with_nss_plugin" != "xno" ; then
      AC_CHECK_HEADERS([nss.h], [
          with_nss_plugin=yes
        ],[
          if test "x$with_nss_plugin" = "xyes" ; then
            fail = 1
          fi
        ])

      if test $fail = 1 ; then
        AC_MSG_ERROR([Can't build nss plugin without nss.h])
      fi
    fi

    if test "x$with_nss_plugin" = "xyes" ; then
      AC_DEFINE_UNQUOTED([NSS], 1, [whether nss plugin is enabled])

      AC_CHECK_TYPE([struct gaih_addrtuple],
        [AC_DEFINE([HAVE_STRUCT_GAIH_ADDRTUPLE], [1],
          [Defined if struct gaih_addrtuple exists in nss.h])],
        [], [[#include <nss.h>
        ]])

      AC_CHECK_TYPES([ns_mtab, nss_module_unregister_fn],
                     [AC_DEFINE([HAVE_BSD_NSS],
                                [1],
                                [whether using BSD style NSS])
                      bsd_nss=yes
                     ],
                     [],
                     [#include <nsswitch.h>])
    fi
  fi

  AM_CONDITIONAL(WITH_NSS, [test "x$with_nss_plugin" = "xyes"])
  AM_CONDITIONAL(WITH_BSD_NSS, [test "x$bsd_nss" = "xyes"])
])

AC_DEFUN([LIBVIRT_RESULT_NSS],[
  LIBVIRT_RESULT([nss], [$with_nss_plugin])
])
