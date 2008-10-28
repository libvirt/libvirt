# sys_ioctl_h.m4 serial 1
dnl Copyright (C) 2008 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

dnl Written by Bruno Haible.

AC_DEFUN([gl_SYS_IOCTL_H],
[
  dnl Use AC_REQUIRE here, so that the default behavior below is expanded
  dnl once only, before all statements that occur in other macros.
  AC_REQUIRE([gl_SYS_IOCTL_H_DEFAULTS])

  AC_CHECK_HEADERS_ONCE([sys/ioctl.h])
  if test $ac_cv_header_sys_ioctl_h = yes; then
    HAVE_SYS_IOCTL_H=1
    dnl Test whether <sys/ioctl.h> declares ioctl(), or whether some other
    dnl header file, such as <unistd.h> or <stropts.h>, is needed for that.
    AC_CACHE_CHECK([whether <sys/ioctl.h> declares ioctl],
      [gl_cv_decl_ioctl_in_sys_ioctl_h],
      [AC_CHECK_DECL([ioctl],
         [gl_cv_decl_ioctl_in_sys_ioctl_h=yes],
         [gl_cv_decl_ioctl_in_sys_ioctl_h=no],
         [#include <sys/ioctl.h>])
      ])
    if test $gl_cv_decl_ioctl_in_sys_ioctl_h != yes; then
      SYS_IOCTL_H='sys/ioctl.h'
    fi
  else
    HAVE_SYS_IOCTL_H=0
    SYS_IOCTL_H='sys/ioctl.h'
  fi
  AC_SUBST([HAVE_SYS_IOCTL_H])
  dnl Execute this unconditionally, because SYS_IOCTL_H may be set by other
  dnl modules, after this code is executed.
  gl_CHECK_NEXT_HEADERS([sys/ioctl.h])
])

dnl Unconditionally enables the replacement of <sys/ioctl.h>.
AC_DEFUN([gl_REPLACE_SYS_IOCTL_H],
[
  AC_REQUIRE([gl_SYS_IOCTL_H_DEFAULTS])
  SYS_IOCTL_H='sys/ioctl.h'
])

AC_DEFUN([gl_SYS_IOCTL_MODULE_INDICATOR],
[
  dnl Use AC_REQUIRE here, so that the default settings are expanded once only.
  AC_REQUIRE([gl_SYS_IOCTL_H_DEFAULTS])
  GNULIB_[]m4_translit([$1],[abcdefghijklmnopqrstuvwxyz./-],[ABCDEFGHIJKLMNOPQRSTUVWXYZ___])=1
])

AC_DEFUN([gl_SYS_IOCTL_H_DEFAULTS],
[
  GNULIB_IOCTL=0;         AC_SUBST([GNULIB_IOCTL])
  dnl Assume proper GNU behavior unless another module says otherwise.
  SYS_IOCTL_H_HAVE_WINSOCK2_H=0; AC_SUBST([SYS_IOCTL_H_HAVE_WINSOCK2_H])
  SYS_IOCTL_H='';                AC_SUBST([SYS_IOCTL_H])
])
