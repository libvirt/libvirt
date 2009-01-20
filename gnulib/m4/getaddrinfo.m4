# getaddrinfo.m4 serial 20
dnl Copyright (C) 2004-2009 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

AC_DEFUN([gl_GETADDRINFO],
[
  AC_REQUIRE([gl_HEADER_SYS_SOCKET])dnl for HAVE_SYS_SOCKET_H, HAVE_WINSOCK2_H
  AC_REQUIRE([gl_HEADER_NETDB])dnl for HAVE_NETDB_H
  AC_MSG_NOTICE([checking how to do getaddrinfo, freeaddrinfo and getnameinfo])
  GETADDRINFO_LIB=
  gai_saved_LIBS="$LIBS"

  dnl Where is getaddrinfo()?
  dnl - On Solaris, it is in libsocket.
  dnl - On Haiku, it is in libnetwork.
  dnl - On BeOS, it is in libnet.
  dnl - On native Windows, it is in ws2_32.dll.
  dnl - Otherwise it is in libc.
  AC_SEARCH_LIBS([getaddrinfo], [socket network net],
    [if test "$ac_cv_search_getaddrinfo" != "none required"; then
       GETADDRINFO_LIB="$ac_cv_search_getaddrinfo"
     fi])
  LIBS="$gai_saved_LIBS $GETADDRINFO_LIB"

  AC_CACHE_CHECK([for getaddrinfo], [gl_cv_func_getaddrinfo], [
    AC_TRY_LINK([
#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#include <stddef.h>
], [getaddrinfo("", "", NULL, NULL);],
      [gl_cv_func_getaddrinfo=yes],
      [gl_cv_func_getaddrinfo=no])])
  if test $gl_cv_func_getaddrinfo = no; then
    AC_CACHE_CHECK([for getaddrinfo in ws2tcpip.h and -lws2_32],
		   gl_cv_w32_getaddrinfo, [
      gl_cv_w32_getaddrinfo=no
      am_save_LIBS="$LIBS"
      LIBS="$LIBS -lws2_32"
      AC_TRY_LINK([
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
#include <stddef.h>
], [getaddrinfo(NULL, NULL, NULL, NULL);], gl_cv_w32_getaddrinfo=yes)
      LIBS="$am_save_LIBS"
    ])
    if test "$gl_cv_w32_getaddrinfo" = "yes"; then
      GETADDRINFO_LIB="-lws2_32"
      LIBS="$gai_saved_LIBS $GETADDRINFO_LIB"
    else
      AC_LIBOBJ([getaddrinfo])
    fi
  fi

  # We can't use AC_REPLACE_FUNCS here because gai_strerror may be an
  # inline function declared in ws2tcpip.h, so we need to get that
  # header included somehow.
  AC_CACHE_CHECK([for gai_strerror (possibly via ws2tcpip.h)],
    gl_cv_func_gai_strerror, [
      AC_TRY_LINK([
#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
#include <stddef.h>
], [gai_strerror (NULL);],
        [gl_cv_func_gai_strerror=yes],
        [gl_cv_func_gai_strerror=no])])
  if test $gl_cv_func_gai_strerror = no; then
    AC_LIBOBJ([gai_strerror])
  fi

  LIBS="$gai_saved_LIBS"

  gl_PREREQ_GETADDRINFO

  AC_SUBST([GETADDRINFO_LIB])
])

# Prerequisites of lib/netdb.in.h and lib/getaddrinfo.c.
AC_DEFUN([gl_PREREQ_GETADDRINFO], [
  AC_REQUIRE([gl_NETDB_H_DEFAULTS])
  AC_REQUIRE([gl_HEADER_SYS_SOCKET])dnl for HAVE_SYS_SOCKET_H, HAVE_WINSOCK2_H
  AC_REQUIRE([gl_HOSTENT]) dnl for HOSTENT_LIB
  AC_REQUIRE([gl_SERVENT]) dnl for SERVENT_LIB
  AC_REQUIRE([AC_C_RESTRICT])
  AC_REQUIRE([gl_SOCKET_FAMILIES])
  AC_REQUIRE([gl_HEADER_SYS_SOCKET])
  AC_REQUIRE([AC_C_INLINE])
  AC_REQUIRE([AC_USE_SYSTEM_EXTENSIONS])

  dnl Including sys/socket.h is wrong for Windows, but Windows does not
  dnl have sa_len so the result is correct anyway.
  AC_CHECK_MEMBERS([struct sockaddr.sa_len], , , [#include <sys/socket.h>])

  AC_CHECK_HEADERS_ONCE([netinet/in.h])

  AC_CHECK_DECLS([getaddrinfo, freeaddrinfo, gai_strerror, getnameinfo],,,[
  /* sys/types.h is not needed according to POSIX, but the
     sys/socket.h in i386-unknown-freebsd4.10 and
     powerpc-apple-darwin5.5 required it. */
#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
])
  if test $ac_cv_have_decl_getaddrinfo = no; then
    HAVE_DECL_GETADDRINFO=0
  fi
  if test $ac_cv_have_decl_freeaddrinfo = no; then
    HAVE_DECL_FREEADDRINFO=0
  fi
  if test $ac_cv_have_decl_gai_strerror = no; then
    HAVE_DECL_GAI_STRERROR=0
  fi
  if test $ac_cv_have_decl_getnameinfo = no; then
    HAVE_DECL_GETNAMEINFO=0
  fi

  AC_CHECK_TYPES([struct addrinfo],,,[
#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
])
  if test $ac_cv_type_struct_addrinfo = no; then
    HAVE_STRUCT_ADDRINFO=0
  fi

  dnl Append $HOSTENT_LIB to GETADDRINFO_LIB, avoiding gratuitous duplicates.
  case " $GETADDRINFO_LIB " in
    *" $HOSTENT_LIB "*) ;;
    *) GETADDRINFO_LIB="$GETADDRINFO_LIB $HOSTENT_LIB" ;;
  esac

  dnl Append $SERVENT_LIB to GETADDRINFO_LIB, avoiding gratuitous duplicates.
  case " $GETADDRINFO_LIB " in
    *" $SERVENT_LIB "*) ;;
    *) GETADDRINFO_LIB="$GETADDRINFO_LIB $SERVENT_LIB" ;;
  esac
])
