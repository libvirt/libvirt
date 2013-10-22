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
 * The only way avoid to avoid such deps is to re-compile the
 * functions with the code in question disabled, and for that we
 * must override the main config.h rules. Hence this file :-(
 */

#ifdef LIBVIRT_SETUID_RPC_CLIENT
# undef HAVE_LIBDEVMAPPER_H
# undef HAVE_LIBNL
# undef HAVE_LIBNL3
# undef HAVE_LIBSASL2
# undef WITH_CAPNG
# undef WITH_CURL
# undef WITH_DTRACE_PROBES
# undef WITH_GNUTLS
# undef WITH_GNUTLS_GCRYPT
# undef WITH_MACVTAP
# undef WITH_NUMACTL
# undef WITH_SASL
# undef WITH_SSH2
# undef WITH_VIRTUALPORT
# undef WITH_YAJL
# undef WITH_YAJL2
#endif
