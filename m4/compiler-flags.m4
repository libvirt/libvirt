# serial 3
# Find valid warning flags for the C Compiler.           -*-Autoconf-*-
#
# Copyright (C) 2001, 2002, 2006 Free Software Foundation, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301  USA

# Written by Jesse Thilo.

AC_DEFUN([gl_COMPILER_FLAGS],
  [AC_MSG_CHECKING(whether compiler accepts $1)
   AC_SUBST(COMPILER_FLAGS)
   ac_save_CFLAGS="$CFLAGS"
   CFLAGS="$CFLAGS $1"
   AC_TRY_LINK([], [], has_option=yes, has_option=no,)
   echo 'int x;' >conftest.c
   $CC $CFLAGS -c conftest.c 2>conftest.err
   ret=$?
   if test $ret != 0 -o -s conftest.err -o $has_option = "no"; then
       AC_MSG_RESULT(no)
   else
       AC_MSG_RESULT(yes)
       COMPILER_FLAGS="$COMPILER_FLAGS $1"
   fi
   CFLAGS="$ac_save_CFLAGS"
   rm -f conftest*
 ])
