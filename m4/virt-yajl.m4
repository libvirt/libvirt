dnl The libyajl.so library
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

AC_DEFUN([LIBVIRT_CHECK_YAJL],[
  dnl YAJL JSON library http://lloyd.github.com/yajl/
  if test "$with_qemu:$with_yajl" = yes:check; then
    dnl Some versions of qemu require the use of yajl; try to detect them
    dnl here, although we do not require qemu to exist in order to compile.
    dnl This check mirrors src/qemu/qemu_capabilities.c
    AC_PATH_PROGS([QEMU], [qemu-kvm qemu kvm qemu-system-x86_64],
                  [], [$PATH:/usr/bin:/usr/libexec])
    if test -x "$QEMU"; then
      if `$QEMU -help | grep libvirt` >/dev/null; then
        with_yajl=yes
      else
        [qemu_version_sed='s/.*ersion \([0-9.,]*\).*/\1/']
        qemu_version=`$QEMU -version | sed "$qemu_version_sed"`
        case $qemu_version in
          [[1-9]].* | 0.15.* ) with_yajl=yes ;;
          0.* | '' ) ;;
          *) AC_MSG_ERROR([Unexpected qemu version string]) ;;
        esac
      fi
    fi
  fi

  LIBVIRT_CHECK_LIB_ALT([YAJL], [yajl],
                        [yajl_parse_complete], [yajl/yajl_common.h],
                        [YAJL2], [yajl],
                        [yajl_tree_parse], [yajl/yajl_common.h])
])

AC_DEFUN([LIBVIRT_RESULT_YAJL],[
  LIBVIRT_RESULT_LIB([YAJL])
])
