/*
 * Copyright (C) 2013 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

/*
 * Since virt-login-shell will be setuid, we must do everything
 * we can to avoid linking to other libraries. Many of them do
 * unsafe things in functions marked __atttribute__((constructor)).
 * The only way to avoid such deps is to re-compile the
 * functions with the code in question disabled, and for that we
 * must override the main config.h rules. Hence this file :-(
 */

#ifdef LIBVIRT_SETUID_RPC_CLIENT
# undef HAVE_LIBNL
# undef HAVE_LIBNL3
# undef HAVE_LIBSASL2
# undef HAVE_SYS_ACL_H
# undef WITH_CAPNG
# undef WITH_CURL
# undef WITH_DBUS
# undef WITH_DEVMAPPER
# undef WITH_DTRACE_PROBES
# undef WITH_GNUTLS
# undef WITH_GNUTLS_GCRYPT
# undef WITH_LIBSSH
# undef WITH_MACVTAP
# undef WITH_NUMACTL
# undef WITH_SASL
# undef WITH_SSH2
# undef WITH_SYSTEMD_DAEMON
# undef WITH_VIRTUALPORT
# undef WITH_YAJL
# undef WITH_YAJL2
#endif

/*
 * With the NSS module it's the same story as virt-login-shell. See the
 * explanation above.
 */
#ifdef LIBVIRT_NSS
# undef HAVE_LIBNL
# undef HAVE_LIBNL3
# undef HAVE_LIBSASL2
# undef HAVE_SYS_ACL_H
# undef WITH_CAPNG
# undef WITH_CURL
# undef WITH_DEVMAPPER
# undef WITH_DTRACE_PROBES
# undef WITH_GNUTLS
# undef WITH_GNUTLS_GCRYPT
# undef WITH_LIBSSH
# undef WITH_MACVTAP
# undef WITH_NUMACTL
# undef WITH_SASL
# undef WITH_SSH2
# undef WITH_VIRTUALPORT
# undef WITH_SECDRIVER_SELINUX
# undef WITH_SECDRIVER_APPARMOR
# undef WITH_CAPNG
#endif /* LIBVIRT_NSS */

/*
 * Define __GNUC_PREREQ to a sane default if it isn't yet defined.
 * This is done here so that it's included as early as possible; gnulib relies
 * on this to be defined in features.h, which should be included from ctype.h.
 * This doesn't happen on many non-glibc systems.
 * When __GNUC_PREREQ is not defined, gnulib defines it to 0, which breaks things.
 */
#ifdef __GNUC__
# ifndef __GNUC_PREREQ
#  if defined __GNUC__ && defined __GNUC_MINOR__
#   define __GNUC_PREREQ(maj, min)                                        \
   ((__GNUC__ << 16) + __GNUC_MINOR__ >= ((maj) << 16) + (min))
#  else
#   define __GNUC_PREREQ(maj, min) 0
#  endif
# endif
#endif
