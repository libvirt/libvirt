dnl The gnutls libgnutls.so library
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

AC_DEFUN([LIBVIRT_CHECK_GNUTLS],[
  LIBVIRT_CHECK_PKG([GNUTLS], [gnutls], [2.2.0])

  dnl Triple probe: gnutls < 2.12 only used gcrypt, gnutls >= 3.0 uses
  dnl only nettle, and versions in between had a configure option.
  dnl Our goal is to avoid gcrypt if we can prove gnutls uses nettle,
  dnl but it is a safe fallback to use gcrypt if we can't prove anything.A

  GNUTLS_GCRYPT=
  if $PKG_CONFIG --exists 'gnutls >= 3.0'; then
    GNUTLS_GCRYPT="no"
  elif $PKG_CONFIG --exists 'gnutls >= 2.12'; then
    GNUTLS_GCRYPT="probe"
  else
    GNUTLS_GCRYPT="yes"
  fi

  if test "$GNUTLS_GCRYPT" = "probe"; then
    case $($PKG_CONFIG --libs --static gnutls) in
      *gcrypt*) GNUTLS_GCRYPT=yes       ;;
      *nettle*) GNUTLS_GCRYPT=no        ;;
      *)        GNUTLS_GCRYPT=unknown   ;;
    esac
  fi

  if test "$GNUTLS_GCRYPT" = "yes" || test "$GNUTLS_GCRYPT" = "unknown"; then
    GNUTLS_LIBS="$GNUTLS_LIBS -lgcrypt"
    dnl We're not using gcrypt deprecated features so define
    dnl GCRYPT_NO_DEPRECATED to avoid deprecated warnings
    GNUTLS_CFLAGS="$GNUTLS_CFLAGS -DGCRYPT_NO_DEPRECATED"
    AC_DEFINE_UNQUOTED([WITH_GNUTLS_GCRYPT], 1,
                       [set to 1 if it is known or assumed that GNUTLS uses gcrypt])
  fi

  AC_CHECK_HEADERS([gnutls/crypto.h], [], [], [[
    #include <gnutls/gnutls.h>
  ]])

  AC_CHECK_FUNC([gnutls_rnd])
  AC_CHECK_FUNC([gnutls_cipher_encrypt])
])

AC_DEFUN([LIBVIRT_RESULT_GNUTLS],[
  LIBVIRT_RESULT_LIB([GNUTLS])
])
