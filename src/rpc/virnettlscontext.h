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
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#ifndef __VIR_NET_TLS_CONTEXT_H__
# define __VIR_NET_TLS_CONTEXT_H__

# include "internal.h"

typedef struct _virNetTLSContext virNetTLSContext;
typedef virNetTLSContext *virNetTLSContextPtr;

typedef struct _virNetTLSSession virNetTLSSession;
typedef virNetTLSSession *virNetTLSSessionPtr;


void virNetTLSInit(void);

virNetTLSContextPtr virNetTLSContextNewServerPath(const char *pkipath,
                                                  bool tryUserPkiPath,
                                                  const char *const*x509dnWhitelist,
                                                  bool sanityCheckCert,
                                                  bool requireValidCert);

virNetTLSContextPtr virNetTLSContextNewClientPath(const char *pkipath,
                                                  bool tryUserPkiPath,
                                                  bool sanityCheckCert,
                                                  bool requireValidCert);

virNetTLSContextPtr virNetTLSContextNewServer(const char *cacert,
                                              const char *cacrl,
                                              const char *cert,
                                              const char *key,
                                              const char *const*x509dnWhitelist,
                                              bool sanityCheckCert,
                                              bool requireValidCert);

virNetTLSContextPtr virNetTLSContextNewClient(const char *cacert,
                                              const char *cacrl,
                                              const char *cert,
                                              const char *key,
                                              bool sanityCheckCert,
                                              bool requireValidCert);

void virNetTLSContextRef(virNetTLSContextPtr ctxt);

int virNetTLSContextCheckCertificate(virNetTLSContextPtr ctxt,
                                     virNetTLSSessionPtr sess);

void virNetTLSContextFree(virNetTLSContextPtr ctxt);


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

void virNetTLSSessionRef(virNetTLSSessionPtr sess);

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

void virNetTLSSessionFree(virNetTLSSessionPtr sess);


#endif
