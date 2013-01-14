dnl The libcurl.so library
dnl
dnl Copyright (C) 2012-2013 Red Hat, Inc.
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

AC_DEFUN([LIBVIRT_CHECK_CURL],[
  LIBVIRT_CHECK_PKG([CURL], [libcurl], [7.18.0])

  # XXX as of libcurl-devel-7.20.1-3.fc13.x86_64, curl ships a version
  # of <curl/curl.h> that #defines several wrapper macros around underlying
  # functions to add type safety for gcc only.  However, these macros
  # spuriously trip gcc's -Wlogical-op warning.  Avoid the warning by
  # disabling the wrappers; even if it removes some type-check safety.
  CURL_CFLAGS="-DCURL_DISABLE_TYPECHECK $CURL_CFLAGS"
  AC_SUBST(CURL_CFLAGS)
])

AC_DEFUN([LIBVIRT_RESULT_CURL],[
  LIBVIRT_RESULT_LIB([CURL])
])
