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

#ifndef __VIR_NET_CLIENT_SASL_CONTEXT_H__
# define __VIR_NET_CLIENT_SASL_CONTEXT_H__

# include <sasl/sasl.h>

# include "internal.h"
# include "virobject.h"

typedef struct _virNetSASLContext virNetSASLContext;
typedef virNetSASLContext *virNetSASLContextPtr;

typedef struct _virNetSASLSession virNetSASLSession;
typedef virNetSASLSession *virNetSASLSessionPtr;

enum {
    VIR_NET_SASL_COMPLETE,
    VIR_NET_SASL_CONTINUE,
    VIR_NET_SASL_INTERACT,
};

virNetSASLContextPtr virNetSASLContextNewClient(void);
virNetSASLContextPtr virNetSASLContextNewServer(const char *const*usernameWhitelist);

int virNetSASLContextCheckIdentity(virNetSASLContextPtr ctxt,
                                   const char *identity);

virNetSASLSessionPtr virNetSASLSessionNewClient(virNetSASLContextPtr ctxt,
                                                const char *service,
                                                const char *hostname,
                                                const char *localAddr,
                                                const char *remoteAddr,
                                                sasl_callback_t *cbs);
virNetSASLSessionPtr virNetSASLSessionNewServer(virNetSASLContextPtr ctxt,
                                                const char *service,
                                                const char *localAddr,
                                                const char *remoteAddr);

char *virNetSASLSessionListMechanisms(virNetSASLSessionPtr sasl);

int virNetSASLSessionExtKeySize(virNetSASLSessionPtr sasl,
                                int ssf);

int virNetSASLSessionGetKeySize(virNetSASLSessionPtr sasl);

const char *virNetSASLSessionGetIdentity(virNetSASLSessionPtr sasl);

int virNetSASLSessionSecProps(virNetSASLSessionPtr sasl,
                              int minSSF,
                              int maxSSF,
                              bool allowAnonymous);

int virNetSASLSessionClientStart(virNetSASLSessionPtr sasl,
                                 const char *mechlist,
                                 sasl_interact_t **prompt_need,
                                 const char **clientout,
                                 size_t *clientoutlen,
                                 const char **mech);

int virNetSASLSessionClientStep(virNetSASLSessionPtr sasl,
                                const char *serverin,
                                size_t serverinlen,
                                sasl_interact_t **prompt_need,
                                const char **clientout,
                                size_t *clientoutlen);

int virNetSASLSessionServerStart(virNetSASLSessionPtr sasl,
                                 const char *mechname,
                                 const char *clientin,
                                 size_t clientinlen,
                                 const char **serverout,
                                 size_t *serveroutlen);

int virNetSASLSessionServerStep(virNetSASLSessionPtr sasl,
                                const char *clientin,
                                size_t clientinlen,
                                const char **serverout,
                                size_t *serveroutlen);

size_t virNetSASLSessionGetMaxBufSize(virNetSASLSessionPtr sasl);

ssize_t virNetSASLSessionEncode(virNetSASLSessionPtr sasl,
                                const char *input,
                                size_t inputLen,
                                const char **output,
                                size_t *outputlen);

ssize_t virNetSASLSessionDecode(virNetSASLSessionPtr sasl,
                                const char *input,
                                size_t inputLen,
                                const char **output,
                                size_t *outputlen);

#endif /* __VIR_NET_CLIENT_SASL_CONTEXT_H__ */
