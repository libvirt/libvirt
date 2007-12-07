# poll.m4 serial 7
dnl Copyright (c) 2003, 2005, 2006, 2007 Free Software Foundation, Inc.
dnl This file is free software; the Free Software Foundation
dnl gives unlimited permission to copy and/or distribute it,
dnl with or without modifications, as long as this notice is preserved.

AC_DEFUN([gl_FUNC_POLL],
[
  AC_CHECK_HEADERS(poll.h)
  if test "$ac_cv_header_poll_h" = no; then
    gl_cv_func_poll=no
  else
    AC_CHECK_FUNC(poll,
      [# Check whether poll() works on special files (like /dev/null) and
       # and ttys (like /dev/tty). On MacOS X 10.4.0 and AIX 5.3, it doesn't.
       AC_TRY_RUN([
#include <fcntl.h>
#include <poll.h>
         int main()
         {
           struct pollfd ufd;
           /* Try /dev/null for reading.  */
           ufd.fd = open ("/dev/null", O_RDONLY);
           if (ufd.fd < 0)
             /* If /dev/null does not exist, it's not MacOS X nor AIX. */
             return 0;
           ufd.events = POLLIN;
           ufd.revents = 0;
           if (!(poll (&ufd, 1, 0) == 1 && ufd.revents == POLLIN))
             return 1;
           /* Try /dev/null for writing.  */
           ufd.fd = open ("/dev/null", O_WRONLY);
           if (ufd.fd < 0)
             /* If /dev/null does not exist, it's not MacOS X nor AIX. */
             return 0;
           ufd.events = POLLOUT;
           ufd.revents = 0;
           if (!(poll (&ufd, 1, 0) == 1 && ufd.revents == POLLOUT))
             return 1;
           /* Trying /dev/tty may be too environment dependent.  */
           return 0;
         }],
         [gl_cv_func_poll=yes],
         [gl_cv_func_poll=no],
         [# When cross-compiling, assume that poll() works everywhere except on
          # MacOS X or AIX, regardless of its version.
          AC_EGREP_CPP([MacOSX], [
#if (defined(__APPLE__) && defined(__MACH__)) || defined(_AIX)
This is MacOSX or AIX
#endif
], [gl_cv_func_poll=no], [gl_cv_func_poll=yes])])])
  fi
  if test $gl_cv_func_poll = yes; then
    AC_DEFINE([HAVE_POLL], 1,
      [Define to 1 if you have the 'poll' function and it works.])
    POLL_H=
  else
    AC_LIBOBJ(poll)
    AC_DEFINE(poll, rpl_poll,
      [Define to poll if the replacement function should be used.])
    gl_PREREQ_POLL
    POLL_H=poll.h
  fi
  AC_SUBST([POLL_H])
])

# Prerequisites of lib/poll.c.
AC_DEFUN([gl_PREREQ_POLL],
[
  AC_CHECK_HEADERS_ONCE(sys/ioctl.h sys/filio.h)
])
