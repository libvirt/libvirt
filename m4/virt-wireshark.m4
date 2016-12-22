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

AC_DEFUN([LIBVIRT_ARG_WIRESHARK],[
  LIBVIRT_ARG_WITH_FEATURE([WIRESHARK_DISSECTOR], [wireshark], [check], [1.11.3])
  LIBVIRT_ARG_WITH([WS_PLUGINDIR],
                   [wireshark plugins directory for use when installing
                   wireshark plugin], [check])
])

AC_DEFUN([LIBVIRT_CHECK_WIRESHARK],[
  LIBVIRT_CHECK_PKG([WIRESHARK_DISSECTOR], [wireshark], [1.11.3])

  dnl Check for system location of wireshark plugins
  if test "x$with_wireshark_dissector" != "xno" ; then
    if test "x$with_ws_plugindir" = "xcheck" ; then
      ws_plugindir="$($PKG_CONFIG --variable plugindir wireshark)"
      ws_exec_prefix="$($PKG_CONFIG --variable exec_prefix wireshark)"
      ws_modversion="$($PKG_CONFIG --modversion wireshark)"
      if test "x$ws_plugindir" = "x" ; then
        dnl On some systems the plugindir variable may not be stored within pkg config.
        dnl Fall back to older style of constructing the plugin dir path.
        ws_plugindir="$libdir/wireshark/plugins/$ws_modversion"
      else
        if test "x$ws_exec_prefix" = "x" ; then
          dnl If wireshark's exec_prefix cannot be retrieved from pkg-config,
          dnl this is our best bet
          ws_exec_prefix="/usr"
        fi
        dnl Replace wireshark's exec_prefix with our own.
        dnl Note that ${exec_prefix} is kept verbatim at this point in time,
        dnl and will only be expanded later, when make is called: this makes
        dnl it possible to override such prefix at compilation or installation
        dnl time
        ws_plugindir='${exec_prefix}'"${ws_plugindir#$ws_exec_prefix}"
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
