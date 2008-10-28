# gethostname.m4 serial 4
dnl Copyright (C) 2002, 2008 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

AC_DEFUN([gl_FUNC_GETHOSTNAME],
[
  AC_REQUIRE([gl_UNISTD_H_DEFAULTS])
  gl_PREREQ_SYS_H_WINSOCK2
  AC_REPLACE_FUNCS(gethostname)
  if test $ac_cv_func_gethostname = no; then
    HAVE_GETHOSTNAME=0
    gl_PREREQ_GETHOSTNAME
  fi
])

# Prerequisites of lib/gethostname.c.
AC_DEFUN([gl_PREREQ_GETHOSTNAME], [
  AC_CHECK_FUNCS(uname)
])
