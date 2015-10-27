dnl The libvirt.so wireshark plugin
dnl
dnl Copyright (C) 2015 Red Hat, Inc.
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

AC_DEFUN([LIBVIRT_CHECK_WIRESHARK],[
  LIBVIRT_CHECK_PKG([WIRESHARK_DISSECTOR], [wireshark], [1.11.3])

  AC_ARG_WITH([ws-plugindir],
    [AS_HELP_STRING([--with-ws-plugindir],
      [wireshark plugins directory for use when installing wireshark plugin])],
      [], [with_ws_plugindir=check])

  dnl Check for system location of wireshark plugins
  if test "x$with_wireshark_dissector" != "xno" ; then
    if test "x$with_ws_plugindir" = "xcheck" ; then
      ws_plugindir="$($PKG_CONFIG --variable plugindir wireshark)"
      if test "x$ws_plugindir" = "x" ; then
        dnl On some systems the plugindir variable may not be stored within pkg config.
        dnl Fall back to older style of constructing the plugin dir path.
        ws_plugindir="$libdir/wireshark/plugins/$($PKG_CONFIG --modversion wireshark)"
      fi
    elif test "x$with_ws_plugindir" = "xno" || test "x$with_ws_plugindir" = "xyes"; then
      AC_MSG_ERROR([ws-plugindir must be used only with valid path])
    else
      ws_plugindir=$with_ws_plugindir
    fi
  fi

  AC_SUBST([ws_plugindir])
])

AC_DEFUN([LIBVIRT_RESULT_WIRESHARK],[
  LIBVIRT_RESULT_LIB([WIRESHARK_DISSECTOR])
])
