dnl The pcap library
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

AC_DEFUN([LIBVIRT_ARG_LIBPCAP], [
  LIBVIRT_ARG_WITH([LIBPCAP], [libpcap location], [check])
])

AC_DEFUN([LIBVIRT_CHECK_LIBPCAP], [
  LIBPCAP_REQUIRED="1.5.0"
  LIBPCAP_CONFIG="pcap-config"
  LIBPCAP_CFLAGS=""
  LIBPCAP_LIBS=""

  if test "x$with_libpcap" != "xno"; then
    case $with_libpcap in
      ''|yes|check) LIBPCAP_CONFIG="pcap-config" ;;
      *)      LIBPCAP_CONFIG="$with_libpcap/bin/pcap-config" ;;
    esac
    AS_IF([test "x$LIBPCAP_CONFIG" != "x"], [
      AC_MSG_CHECKING(libpcap $LIBPCAP_CONFIG >= $LIBPCAP_REQUIRED )
      if ! $LIBPCAP_CONFIG --libs > /dev/null 2>&1 ; then
        if test "x$with_libpcap" != "xcheck"; then
          AC_MSG_ERROR([You must install libpcap >= $LIBPCAP_REQUIRED to compile libvirt])
        fi
        AC_MSG_RESULT(no)
        with_libpcap="no"
      else
        LIBPCAP_LIBS="`$LIBPCAP_CONFIG --libs`"
        LIBPCAP_CFLAGS="`$LIBPCAP_CONFIG --cflags`"
        with_libpcap="yes"
        AC_MSG_RESULT(yes)
      fi
    ])
  fi

  if test "x$with_libpcap" = "xyes"; then
    AC_DEFINE_UNQUOTED([HAVE_LIBPCAP], 1, [whether libpcap can be used])
  fi

  AC_SUBST([LIBPCAP_CFLAGS])
  AC_SUBST([LIBPCAP_LIBS])
])

AC_DEFUN([LIBVIRT_RESULT_LIBPCAP], [
  LIBVIRT_RESULT_LIB([LIBPCAP])
])
