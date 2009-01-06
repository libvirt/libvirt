# netdb_h.m4 serial 5
dnl Copyright (C) 2008 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

AC_DEFUN([gl_HEADER_NETDB],
[
  AC_REQUIRE([gl_NETDB_H_DEFAULTS])
  gl_CHECK_NEXT_HEADERS([netdb.h])
  if test $ac_cv_header_netdb_h = yes; then
    AC_COMPILE_IFELSE(
      [AC_LANG_PROGRAM([[
         #include <netdb.h>
         struct addrinfo a;
         int b = EAI_OVERFLOW;
         int c = AI_NUMERICSERV;
       ]])],
      [NETDB_H=''], [NETDB_H='netdb.h'])
    HAVE_NETDB_H=1
  else
    NETDB_H='netdb.h'
    HAVE_NETDB_H=0
  fi
  AC_SUBST([HAVE_NETDB_H])
  AC_SUBST([NETDB_H])
])

AC_DEFUN([gl_NETDB_MODULE_INDICATOR],
[
  dnl Use AC_REQUIRE here, so that the default settings are expanded once only.
  AC_REQUIRE([gl_NETDB_H_DEFAULTS])
  GNULIB_[]m4_translit([$1],[abcdefghijklmnopqrstuvwxyz./-],[ABCDEFGHIJKLMNOPQRSTUVWXYZ___])=1
])

AC_DEFUN([gl_NETDB_H_DEFAULTS],
[
  GNULIB_GETADDRINFO=0; AC_SUBST([GNULIB_GETADDRINFO])
  dnl Assume proper GNU behavior unless another module says otherwise.
  HAVE_STRUCT_ADDRINFO=1;   AC_SUBST([HAVE_STRUCT_ADDRINFO])
  HAVE_DECL_FREEADDRINFO=1; AC_SUBST([HAVE_DECL_FREEADDRINFO])
  HAVE_DECL_GAI_STRERROR=1; AC_SUBST([HAVE_DECL_GAI_STRERROR])
  HAVE_DECL_GETADDRINFO=1;  AC_SUBST([HAVE_DECL_GETADDRINFO])
  HAVE_DECL_GETNAMEINFO=1;  AC_SUBST([HAVE_DECL_GETNAMEINFO])
])
