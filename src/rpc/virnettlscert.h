/*
 * virnettlscert.h: TLS x509 certificate helpers
 *
 * Copyright (C) 2010-2024 Red Hat, Inc.
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

#pragma once

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>

#include "internal.h"

int virNetTLSCertSanityCheck(bool isServer,
                             const char *cacertFile,
                             const char *certFile);

int virNetTLSCertValidateCA(gnutls_x509_crt_t cert,
                            bool isServer);

char *virNetTLSCertValidate(gnutls_x509_crt_t cert,
                            bool isServer,
                            const char *hostname,
                            const char *const *x509dnACL);

gnutls_x509_crt_t virNetTLSCertLoadFromFile(const char *certFile,
                                            bool isServer);
