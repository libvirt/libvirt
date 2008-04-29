# sys_select_h.m4 serial 4
dnl Copyright (C) 2006-2008 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

AC_DEFUN([gl_HEADER_SYS_SELECT],
[
  AC_CACHE_CHECK([whether <sys/select.h> is self-contained],
    [gl_cv_header_sys_select_h_selfcontained],
    [
      AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <sys/select.h>]], [[]])],
        [gl_cv_header_sys_select_h_selfcontained=yes],
        [gl_cv_header_sys_select_h_selfcontained=no])
    ])
  if test $gl_cv_header_sys_select_h_selfcontained = yes; then
    SYS_SELECT_H=''
  else
    SYS_SELECT_H='sys/select.h'
    gl_CHECK_NEXT_HEADERS([sys/select.h])
    if test $ac_cv_header_sys_select_h = yes; then
      HAVE_SYS_SELECT_H=1
    else
      HAVE_SYS_SELECT_H=0
    fi
    AC_SUBST([HAVE_SYS_SELECT_H])
  fi
  AC_SUBST([SYS_SELECT_H])
])
