dnl The readline library
dnl
dnl Copyright (C) 2005-2013 Red Hat, Inc.
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

AC_DEFUN([LIBVIRT_CHECK_READLINE],[
  READLINE_LIBS=
  AC_CHECK_HEADERS([readline/readline.h])

  AC_CHECK_LIB([readline], [readline],
	[lv_use_readline=yes; READLINE_LIBS=-lreadline],
	[lv_use_readline=no])

  # If the above test failed, it may simply be that -lreadline requires
  # some termcap-related code, e.g., from one of the following libraries.
  # See if adding one of them to LIBS helps.
  if test $lv_use_readline = no; then
    lv_saved_libs=$LIBS
    LIBS=
    AC_SEARCH_LIBS([tgetent], [ncurses curses termcap termlib])
    case $LIBS in
      no*) ;;  # handle "no" and "none required"
      *) # anything else is a -lLIBRARY
	# Now, check for -lreadline again, also using $LIBS.
	# Note: this time we use a different function, so that
	# we don't get a cached "no" result.
	AC_CHECK_LIB([readline], [rl_initialize],
		[lv_use_readline=yes
		 READLINE_LIBS="-lreadline $LIBS"],,
		[$LIBS])
	;;
    esac
    test $lv_use_readline = no &&
	AC_MSG_WARN([readline library not found])
    LIBS=$lv_saved_libs
  fi

  if test $lv_use_readline = yes; then
    AC_DEFINE_UNQUOTED([USE_READLINE], 1,
		       [whether virsh can use readline])
    READLINE_CFLAGS=-DUSE_READLINE
  else
    READLINE_CFLAGS=
  fi
  AC_SUBST([READLINE_CFLAGS])
])

AC_DEFUN([LIBVIRT_RESULT_READLINE],[
  LIBVIRT_RESULT([readline], [$lv_use_readline],
     [CFLAGS='$READLINE_CFLAGS' LIBS='$READLINE_LIBS'])
])
