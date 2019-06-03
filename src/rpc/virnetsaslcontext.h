/*
 * virnetsaslcontext.h: SASL encryption/auth handling
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
#include <sasl/sasl.h>

#include "virobject.h"

typedef struct _virNetSASLContext virNetSASLContext;

typedef struct _virNetSASLSession virNetSASLSession;

enum {
    VIR_NET_SASL_COMPLETE,
    VIR_NET_SASL_CONTINUE,
    VIR_NET_SASL_INTERACT,
};

virNetSASLContext *virNetSASLContextNewClient(void);
virNetSASLContext *virNetSASLContextNewServer(const char *const *usernameACL,
                                              unsigned int min_ssf);

int virNetSASLContextCheckIdentity(virNetSASLContext *ctxt,
                                   const char *identity);

unsigned int virNetSASLContextGetTCPMinSSF(virNetSASLContext *ctxt);

virNetSASLSession *virNetSASLSessionNewClient(virNetSASLContext *ctxt,
                                                const char *service,
                                                const char *hostname,
                                                const char *localAddr,
                                                const char *remoteAddr,
                                                sasl_callback_t *cbs);
virNetSASLSession *virNetSASLSessionNewServer(virNetSASLContext *ctxt,
                                                const char *service,
                                                const char *localAddr,
                                                const char *remoteAddr);

char *virNetSASLSessionListMechanisms(virNetSASLSession *sasl);

int virNetSASLSessionExtKeySize(virNetSASLSession *sasl,
                                int ssf);

int virNetSASLSessionGetKeySize(virNetSASLSession *sasl);

const char *virNetSASLSessionGetIdentity(virNetSASLSession *sasl);

int virNetSASLSessionSecProps(virNetSASLSession *sasl,
                              int minSSF,
                              int maxSSF,
                              bool allowAnonymous);

int virNetSASLSessionClientStart(virNetSASLSession *sasl,
                                 const char *mechlist,
                                 sasl_interact_t **prompt_need,
                                 const char **clientout,
                                 size_t *clientoutlen,
                                 const char **mech);

int virNetSASLSessionClientStep(virNetSASLSession *sasl,
                                const char *serverin,
                                size_t serverinlen,
                                sasl_interact_t **prompt_need,
                                const char **clientout,
                                size_t *clientoutlen);

int virNetSASLSessionServerStart(virNetSASLSession *sasl,
                                 const char *mechname,
                                 const char *clientin,
                                 size_t clientinlen,
                                 const char **serverout,
                                 size_t *serveroutlen);

int virNetSASLSessionServerStep(virNetSASLSession *sasl,
                                const char *clientin,
                                size_t clientinlen,
                                const char **serverout,
                                size_t *serveroutlen);

size_t virNetSASLSessionGetMaxBufSize(virNetSASLSession *sasl);

ssize_t virNetSASLSessionEncode(virNetSASLSession *sasl,
                                const char *input,
                                size_t inputLen,
                                const char **output,
                                size_t *outputlen);

ssize_t virNetSASLSessionDecode(virNetSASLSession *sasl,
                                const char *input,
                                size_t inputLen,
                                const char **output,
                                size_t *outputlen);
