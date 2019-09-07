dnl Colourful configure
dnl
dnl Copyright (C) 2015 Nobuyoshi Nakada
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

AC_DEFUN([_COLORIZE_RESULT_PREPARE], [
    msg_checking= msg_result_yes= msg_result_no= msg_result_other= msg_reset=
    AS_IF([test -t 1], [
	msg_begin="`tput smso 2>/dev/null`"
	AS_CASE(["$msg_begin"], ['@<:@'*m],
	    [msg_begin="`echo "$msg_begin" | sed ['s/[0-9]*m$//']`"
	    msg_checking="${msg_begin}33m"
	    AS_IF([test ${TEST_COLORS:+set}], [
		msg_result_yes=[`expr ":$TEST_COLORS:" : ".*:pass=\([^:]*\):"`]
		msg_result_no=[`expr ":$TEST_COLORS:" : ".*:fail=\([^:]*\):"`]
		msg_result_other=[`expr ":$TEST_COLORS:" : ".*:skip=\([^:]*\):"`]
	    ])
	    msg_result_yes="${msg_begin}${msg_result_yes:-32;1}m"
	    msg_result_no="${msg_begin}${msg_result_no:-31;1}m"
	    msg_result_other="${msg_begin}${msg_result_other:-33;1}m"
	    msg_reset="${msg_begin}m"
	    ])
	AS_UNSET(msg_begin)
	])
    AS_REQUIRE_SHELL_FN([colorize_result],
	[AS_FUNCTION_DESCRIBE([colorize_result], [MSG], [Colorize result])],
        [AS_CASE(["$[]1"],
            [yes], [AS_ECHO(["${msg_result_yes}$[]1${msg_reset}]")],
            [no], [AS_ECHO(["${msg_result_no}$[]1${msg_reset}]")],
            [AS_ECHO(["${msg_result_other}$[]1${msg_reset}]")])])
])

AC_DEFUN([COLORIZE_RESULT], [AC_REQUIRE([_COLORIZE_RESULT_PREPARE])dnl
    AS_LITERAL_IF([$1],
	[m4_case([$1],
		[yes], [AS_ECHO(["${msg_result_yes}$1${msg_reset}"])],
		[no], [AS_ECHO(["${msg_result_no}$1${msg_reset}"])],
		[AS_ECHO(["${msg_result_other}$1${msg_reset}"])])],
	[colorize_result "$1"]) dnl
])

AC_DEFUN([AC_CHECKING],[dnl
AC_REQUIRE([_COLORIZE_RESULT_PREPARE])dnl
AS_MESSAGE([checking ${msg_checking}$1${msg_reset}...])])

AC_DEFUN([AC_MSG_RESULT], [dnl
{ _AS_ECHO_LOG([result: $1])
COLORIZE_RESULT([$1]); dnl
}])
