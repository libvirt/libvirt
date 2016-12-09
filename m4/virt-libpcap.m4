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
  LIBVIRT_ARG_WITH_ALT([LIBPCAP], [libpcap location], [check])
])

AC_DEFUN([LIBVIRT_CHECK_LIBPCAP], [
  LIBPCAP_REQUIRED="1.0.0"
  LIBPCAP_CONFIG="pcap-config"
  LIBPCAP_CFLAGS=""
  LIBPCAP_LIBS=""
  LIBPCAP_FOUND="no"

  if test "$with_qemu" = "yes"; then
    case $with_libpcap in
      no)     LIBPCAP_CONFIG= ;;
      ''|yes|check) LIBPCAP_CONFIG="pcap-config" ;;
      *)      LIBPCAP_CONFIG="$with_libpcap/bin/pcap-config" ;;
    esac
    AS_IF([test "x$LIBPCAP_CONFIG" != "x"], [
      AC_MSG_CHECKING(libpcap $LIBPCAP_CONFIG >= $LIBPCAP_REQUIRED )
      if ! $LIBPCAP_CONFIG --libs > /dev/null 2>&1 ; then
        AC_MSG_RESULT(no)
      else
        LIBPCAP_LIBS="`$LIBPCAP_CONFIG --libs`"
        LIBPCAP_CFLAGS="`$LIBPCAP_CONFIG --cflags`"
        LIBPCAP_FOUND="yes"
        AC_MSG_RESULT(yes)
      fi
    ])
  fi

  if test "x$LIBPCAP_FOUND" = "xyes"; then
    AC_DEFINE_UNQUOTED([HAVE_LIBPCAP], 1, [whether libpcap can be used])
    with_libpcap="yes"
  else
    with_libpcap="no"
  fi

  AC_SUBST([LIBPCAP_CFLAGS])
  AC_SUBST([LIBPCAP_LIBS])
])

AC_DEFUN([LIBVIRT_RESULT_LIBPCAP], [
  LIBVIRT_RESULT_LIB([LIBPCAP])
])
