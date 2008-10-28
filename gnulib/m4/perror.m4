# perror.m4 serial 1
dnl Copyright (C) 2008 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

AC_DEFUN([gl_FUNC_PERROR],
[
  AC_REQUIRE([gl_STDIO_H_DEFAULTS])
  AC_REQUIRE([gl_HEADER_ERRNO_H])
  if test -n "$ERRNO_H"; then
    dnl The system's perror() cannot know about the new errno values we add
    dnl to <errno.h>. Replace it.
    REPLACE_PERROR=1
    AC_LIBOBJ([perror])
  fi
])
