/*
 * gnutls_1_0_compat.h: GnuTLS 1.0 compatibility
 *
 * Copyright (C) 2007 Red Hat, Inc.
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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 *
 * Author: Richard W.M. Jones <rjones@redhat.com>
 */

#ifndef LIBVIRT_GNUTLS_1_0_COMPAT_H__
# define LIBVIRT_GNUTLS_1_0_COMPAT_H__

# include <config.h>

# include <gnutls/gnutls.h>

/* enable backward compatibility macros for gnutls 1.x.y */
# if LIBGNUTLS_VERSION_MAJOR < 2
#  define GNUTLS_1_0_COMPAT
# endif

# ifdef GNUTLS_1_0_COMPAT
#  define gnutls_session_t                 gnutls_session
#  define gnutls_x509_crt_t                gnutls_x509_crt
#  define gnutls_dh_params_t               gnutls_dh_params
#  define gnutls_transport_ptr_t           gnutls_transport_ptr
#  define gnutls_datum_t                   gnutls_datum
#  define gnutls_certificate_credentials_t gnutls_certificate_credentials
#  define gnutls_cipher_algorithm_t        gnutls_cipher_algorithm
# endif

#endif /* LIBVIRT_GNUTLS_1_0_COMPAT_H__ */
