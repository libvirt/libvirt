/*
 * virnetserverclient.h: generic network RPC server client
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
 * Copyright (C) 2006 Daniel P. Berrange
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
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_NET_SERVER_CLIENT_H__
# define __VIR_NET_SERVER_CLIENT_H__

# include "virnetsocket.h"
# include "virnetmessage.h"

typedef struct _virNetServerClient virNetServerClient;
typedef virNetServerClient *virNetServerClientPtr;

typedef int (*virNetServerClientDispatchFunc)(virNetServerClientPtr client,
                                              virNetMessagePtr msg,
                                              void *opaque);

typedef int (*virNetServerClientFilterFunc)(virNetServerClientPtr client,
                                            virNetMessagePtr msg,
                                            void *opaque);

virNetServerClientPtr virNetServerClientNew(virNetSocketPtr sock,
                                            int auth,
                                            bool readonly,
                                            size_t nrequests_max,
                                            virNetTLSContextPtr tls);

int virNetServerClientAddFilter(virNetServerClientPtr client,
                                virNetServerClientFilterFunc func,
                                void *opaque);

void virNetServerClientRemoveFilter(virNetServerClientPtr client,
                                    int filterID);

int virNetServerClientGetAuth(virNetServerClientPtr client);
bool virNetServerClientGetReadonly(virNetServerClientPtr client);

bool virNetServerClientHasTLSSession(virNetServerClientPtr client);
int virNetServerClientGetTLSKeySize(virNetServerClientPtr client);

# ifdef HAVE_SASL
void virNetServerClientSetSASLSession(virNetServerClientPtr client,
                                      virNetSASLSessionPtr sasl);
# endif

int virNetServerClientGetFD(virNetServerClientPtr client);

bool virNetServerClientIsSecure(virNetServerClientPtr client);

int virNetServerClientSetIdentity(virNetServerClientPtr client,
                                  const char *identity);
const char *virNetServerClientGetIdentity(virNetServerClientPtr client);

int virNetServerClientGetUNIXIdentity(virNetServerClientPtr client,
                                      uid_t *uid, gid_t *gid, pid_t *pid);

void virNetServerClientRef(virNetServerClientPtr client);

typedef void (*virNetServerClientFreeFunc)(void *data);

void virNetServerClientSetPrivateData(virNetServerClientPtr client,
                                      void *opaque,
                                      virNetServerClientFreeFunc ff);
void *virNetServerClientGetPrivateData(virNetServerClientPtr client);

typedef void (*virNetServerClientCloseFunc)(virNetServerClientPtr client);

void virNetServerClientSetCloseHook(virNetServerClientPtr client,
                                    virNetServerClientCloseFunc cf);

void virNetServerClientSetDispatcher(virNetServerClientPtr client,
                                     virNetServerClientDispatchFunc func,
                                     void *opaque);
void virNetServerClientClose(virNetServerClientPtr client);
bool virNetServerClientIsClosed(virNetServerClientPtr client);

void virNetServerClientDelayedClose(virNetServerClientPtr client);
void virNetServerClientImmediateClose(virNetServerClientPtr client);
bool virNetServerClientWantClose(virNetServerClientPtr client);

int virNetServerClientInit(virNetServerClientPtr client);

int virNetServerClientInitKeepAlive(virNetServerClientPtr client,
                                    int interval,
                                    unsigned int count);
bool virNetServerClientCheckKeepAlive(virNetServerClientPtr client,
                                      virNetMessagePtr msg);
int virNetServerClientStartKeepAlive(virNetServerClientPtr client);

const char *virNetServerClientLocalAddrString(virNetServerClientPtr client);
const char *virNetServerClientRemoteAddrString(virNetServerClientPtr client);

int virNetServerClientSendMessage(virNetServerClientPtr client,
                                  virNetMessagePtr msg);

bool virNetServerClientNeedAuth(virNetServerClientPtr client);

void virNetServerClientFree(virNetServerClientPtr client);


#endif /* __VIR_NET_SERVER_CLIENT_H__ */
