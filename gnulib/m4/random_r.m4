# serial 1
dnl Copyright (C) 2008 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

AC_DEFUN([gl_FUNC_RANDOM_R],
[
  AC_REQUIRE([gl_STDLIB_H_DEFAULTS])
  AC_CHECK_FUNCS([random_r])
  if test $ac_cv_func_random_r = no; then
    HAVE_RANDOM_R=0
    AC_LIBOBJ([random_r])
    gl_PREREQ_RANDOM_R
  fi
])

# Prerequisites of lib/random_r.c.
AC_DEFUN([gl_PREREQ_RANDOM_R], [
  :
])
