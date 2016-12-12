dnl The libpthread.so library
dnl
dnl Copyright (C) 2016 Red Hat, Inc.
dnl
dnl This library is free software; you can redistribute it and/or
dnl modify it under the terms of the GNU Lesser General Public
dnl License as published by the Free Software Foundation; either
dnl version 2.1 of the License, or (at your option) any later version.
dnl
dnl This library is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
dnl Lesser General Public License for more details.
dnl
dnl You should have received a copy of the GNU Lesser General Public
dnl License along with this library.  If not, see
dnl <http://www.gnu.org/licenses/>.
dnl

AC_DEFUN([LIBVIRT_CHECK_PTHREAD], [
  old_LIBS="$LIBS"

  dnl Availability of pthread functions. Because of $LIB_PTHREAD, we
  dnl cannot use AC_CHECK_FUNCS_ONCE. LIB_PTHREAD and LIBMULTITHREAD
  dnl were set during gl_INIT by gnulib.
  LIBS="$LIBS $LIB_PTHREAD $LIBMULTITHREAD"
  pthread_found=yes
  AC_CHECK_FUNCS([pthread_mutexattr_init])
  AC_CHECK_HEADER([pthread.h],,[pthread_found=no])

  if test "$ac_cv_func_pthread_mutexattr_init:$pthread_found" != "yes:yes"
  then
    AC_MSG_ERROR([A pthreads impl is required for building libvirt])
  fi

  dnl At least mingw64-winpthreads #defines pthread_sigmask to 0,
  dnl which in turn causes compilation to complain about unused variables.
  dnl Expose this broken implementation, so we can work around it.
  AC_CACHE_CHECK([whether pthread_sigmask does anything],
    [lv_cv_pthread_sigmask_works],
    [AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
      #include <sys/types.h>
      #include <signal.h>
    ]], [[
      #ifdef pthread_sigmask
      int (*foo)(int, const sigset_t *, sigset_t *) = &pthread_sigmask;
      return !foo;
      #endif
    ]])], [lv_cv_pthread_sigmask_works=yes], [lv_cv_pthread_sigmask_works=no])])
  if test "x$lv_cv_pthread_sigmask_works" != xyes; then
    AC_DEFINE([FUNC_PTHREAD_SIGMASK_BROKEN], [1],
      [Define to 1 if pthread_sigmask is not a real function])
  fi

  LIBS="$old_LIBS"
])
