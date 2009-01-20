# sockets.m4 serial 4
dnl Copyright (C) 2008, 2009 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

AC_DEFUN([gl_SOCKETS],
[
  gl_PREREQ_SYS_H_WINSOCK2 dnl for HAVE_WINSOCK2_H
  LIBSOCKET=
  if test $HAVE_WINSOCK2_H = 1; then
    dnl Native Windows API (not Cygwin).
    AC_CACHE_CHECK([if we need to call WSAStartup in winsock2.h and -lws2_32],
                   [gl_cv_func_wsastartup], [
      gl_save_LIBS="$LIBS"
      LIBS="$LIBS -lws2_32"
      AC_TRY_LINK([
#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif], [
        WORD wVersionRequested = MAKEWORD(1, 1);
        WSADATA wsaData;
        int err = WSAStartup(wVersionRequested, &wsaData);
        WSACleanup ();],
        gl_cv_func_wsastartup=yes, gl_cv_func_wsastartup=no)
      LIBS="$gl_save_LIBS"
    ])
    if test "$gl_cv_func_wsastartup" = "yes"; then
      AC_DEFINE([WINDOWS_SOCKETS], [1], [Define if WSAStartup is needed.])
      LIBSOCKET='-lws2_32'
    fi
  else
    dnl Unix API.
    dnl Solaris has most socket functions in libsocket.
    dnl Haiku has most socket functions in libnetwork.
    dnl BeOS has most socket functions in libnet.
    AC_CACHE_CHECK([for library containing setsockopt], [gl_cv_lib_socket], [
      gl_cv_lib_socket=
      AC_TRY_LINK([extern
#ifdef __cplusplus
"C"
#endif
char setsockopt();], [setsockopt();],
        [],
        [gl_save_LIBS="$LIBS"
         LIBS="$gl_save_LIBS -lsocket"
         AC_TRY_LINK([extern
#ifdef __cplusplus
"C"
#endif
char setsockopt();], [setsockopt();],
           [gl_cv_lib_socket="-lsocket"])
         if test -z "$gl_cv_lib_socket"; then
           LIBS="$gl_save_LIBS -lnetwork"
           AC_TRY_LINK([extern
#ifdef __cplusplus
"C"
#endif
char setsockopt();], [setsockopt();],
             [gl_cv_lib_socket="-lnetwork"])
           if test -z "$gl_cv_lib_socket"; then
             LIBS="$gl_save_LIBS -lnet"
             AC_TRY_LINK([extern
#ifdef __cplusplus
"C"
#endif
char setsockopt();], [setsockopt();],
               [gl_cv_lib_socket="-lnet"])
           fi
         fi
         LIBS="$gl_save_LIBS"
        ])
      if test -z "$gl_cv_lib_socket"; then
        gl_cv_lib_socket="none needed"
      fi
    ])
    if test "$gl_cv_lib_socket" != "none needed"; then
      LIBSOCKET="$gl_cv_lib_socket"
    fi
  fi
  AC_SUBST([LIBSOCKET])
  gl_PREREQ_SOCKETS
])

# Prerequisites of lib/sockets.c.
AC_DEFUN([gl_PREREQ_SOCKETS], [
  :
])
