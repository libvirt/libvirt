dnl The atomic implementation check
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

AC_DEFUN([LIBVIRT_CHECK_ATOMIC], [
  AC_REQUIRE([LIBVIRT_CHECK_PTHREAD])

  dnl We need to decide at configure time if libvirt will use real atomic
  dnl operations ("lock free") or emulated ones with a mutex.
  dnl
  dnl Note that the atomic ops are only available with GCC on x86 when
  dnl using -march=i486 or higher.  If we detect that the atomic ops are
  dnl not available but would be available given the right flags, we want
  dnl to abort and advise the user to fix their CFLAGS.  It's better to do
  dnl that then to silently fall back on emulated atomic ops just because
  dnl the user had the wrong build environment.

  atomic_ops=

  AC_MSG_CHECKING([for atomic ops implementation])

  AC_TRY_COMPILE([], [__GCC_HAVE_SYNC_COMPARE_AND_SWAP_4;],[
    atomic_ops=gcc
  ],[])

  if test "$atomic_ops" = "" ; then
    SAVE_CFLAGS="${CFLAGS}"
    CFLAGS="-march=i486"
    AC_TRY_COMPILE([],
                   [__GCC_HAVE_SYNC_COMPARE_AND_SWAP_4;],
                   [AC_MSG_ERROR([Libvirt must be built with -march=i486 or later.])],
                   [])
    CFLAGS="${SAVE_CFLAGS}"

    case "$host" in
      *-*-mingw* | *-*-msvc* )
        atomic_ops=win32
        ;;
      *)
        if test "$ac_cv_header_pthread_h" = "yes" ; then
          atomic_ops=pthread
        else
          AC_MSG_ERROR([Libvirt must be built with GCC or have pthread.h on non-Win32 platforms])
        fi
        ;;
    esac
  fi

  case "$atomic_ops" in
    gcc)
      AC_DEFINE([VIR_ATOMIC_OPS_GCC],[1],[Use GCC atomic ops])
      ;;
    win32)
      AC_DEFINE([VIR_ATOMIC_OPS_WIN32],[1],[Use Win32 atomic ops])
      ;;
    pthread)
      AC_DEFINE([VIR_ATOMIC_OPS_PTHREAD],[1],[Use pthread atomic ops emulation])
      ;;
  esac
  AM_CONDITIONAL([WITH_ATOMIC_OPS_PTHREAD],[test "$atomic_ops" = "pthread"])
  AC_MSG_RESULT([$atomic_ops])
])
