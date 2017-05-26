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

AC_DEFUN([LIBVIRT_ARG_READLINE],[
  LIBVIRT_ARG_WITH_FEATURE([READLINE], [readline], [check])
])

AC_DEFUN([LIBVIRT_CHECK_READLINE],[
  extra_LIBS=
  lv_saved_libs=$LIBS
  if test "x$with_readline" != xno; then
    # Linking with -lreadline may require some termcap-related code, e.g.,
    # from one of the following libraries.  Add it to LIBS before using
    # canned library checks; then verify later if it was needed.
    LIBS=
    AC_SEARCH_LIBS([tgetent], [ncurses curses termcap termlib])
    case $LIBS in
      no*) ;;  # handle "no" and "none required"
      *) # anything else is a -lLIBRARY
	extra_LIBS=$LIBS ;;
    esac
    LIBS="$lv_saved_libs $extra_LIBS"
  fi

  # The normal library check...
  LIBVIRT_CHECK_LIB([READLINE], [readline], [readline], [readline/readline.h])

  # Touch things up to avoid $extra_LIBS, if possible.  Test a second
  # function, to ensure we aren't being confused by caching.
  LIBS=$lv_saved_libs
  AC_CHECK_LIB([readline], [rl_initialize],
    [READLINE_CFLAGS="-D_FUNCTION_DEF $READLINE_CFLAGS"
     AC_SUBST(READLINE_CFLAGS)],
    [READLINE_LIBS="$READLINE_LIBS $extra_LIBS"])
  LIBS=$lv_saved_libs
])

AC_DEFUN([LIBVIRT_RESULT_READLINE],[
  LIBVIRT_RESULT_LIB([READLINE])
])
