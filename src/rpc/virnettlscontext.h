/*
 * virnettlscontext.h: TLS encryption/x509 handling
 *
 * Copyright (C) 2010-2011 Red Hat, Inc.
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

#include "internal.h"
#include "virobject.h"

typedef struct _virNetTLSContext virNetTLSContext;
typedef virNetTLSContext *virNetTLSContextPtr;

typedef struct _virNetTLSSession virNetTLSSession;
typedef virNetTLSSession *virNetTLSSessionPtr;


void virNetTLSInit(void);

virNetTLSContextPtr virNetTLSContextNewServerPath(const char *pkipath,
                                                  bool tryUserPkiPath,
                                                  const char *const*x509dnWhitelist,
                                                  const char *priority,
                                                  bool sanityCheckCert,
                                                  bool requireValidCert);

virNetTLSContextPtr virNetTLSContextNewClientPath(const char *pkipath,
                                                  bool tryUserPkiPath,
                                                  const char *priority,
                                                  bool sanityCheckCert,
                                                  bool requireValidCert);

virNetTLSContextPtr virNetTLSContextNewServer(const char *cacert,
                                              const char *cacrl,
                                              const char *cert,
                                              const char *key,
                                              const char *const*x509dnWhitelist,
                                              const char *priority,
                                              bool sanityCheckCert,
                                              bool requireValidCert);

virNetTLSContextPtr virNetTLSContextNewClient(const char *cacert,
                                              const char *cacrl,
                                              const char *cert,
                                              const char *key,
                                              const char *priority,
                                              bool sanityCheckCert,
                                              bool requireValidCert);

int virNetTLSContextCheckCertificate(virNetTLSContextPtr ctxt,
                                     virNetTLSSessionPtr sess);


typedef ssize_t (*virNetTLSSessionWriteFunc)(const char *buf, size_t len,
                                             void *opaque);
typedef ssize_t (*virNetTLSSessionReadFunc)(char *buf, size_t len,
                                            void *opaque);

virNetTLSSessionPtr virNetTLSSessionNew(virNetTLSContextPtr ctxt,
                                        const char *hostname);

void virNetTLSSessionSetIOCallbacks(virNetTLSSessionPtr sess,
                                    virNetTLSSessionWriteFunc writeFunc,
                                    virNetTLSSessionReadFunc readFunc,
                                    void *opaque);

ssize_t virNetTLSSessionWrite(virNetTLSSessionPtr sess,
                              const char *buf, size_t len);
ssize_t virNetTLSSessionRead(virNetTLSSessionPtr sess,
                             char *buf, size_t len);

int virNetTLSSessionHandshake(virNetTLSSessionPtr sess);

typedef enum {
    VIR_NET_TLS_HANDSHAKE_COMPLETE,
    VIR_NET_TLS_HANDSHAKE_SENDING,
    VIR_NET_TLS_HANDSHAKE_RECVING,
} virNetTLSSessionHandshakeStatus;

virNetTLSSessionHandshakeStatus
virNetTLSSessionGetHandshakeStatus(virNetTLSSessionPtr sess);

int virNetTLSSessionGetKeySize(virNetTLSSessionPtr sess);

const char *virNetTLSSessionGetX509DName(virNetTLSSessionPtr sess);
