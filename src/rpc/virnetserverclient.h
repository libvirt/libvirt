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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_NET_SERVER_CLIENT_H__
# define __VIR_NET_SERVER_CLIENT_H__

# include "viridentity.h"
# include "virnetsocket.h"
# include "virnetmessage.h"
# include "virobject.h"
# include "virjson.h"

typedef struct _virNetServerClient virNetServerClient;
typedef virNetServerClient *virNetServerClientPtr;

typedef int (*virNetServerClientDispatchFunc)(virNetServerClientPtr client,
                                              virNetMessagePtr msg,
                                              void *opaque);

typedef int (*virNetServerClientFilterFunc)(virNetServerClientPtr client,
                                            virNetMessagePtr msg,
                                            void *opaque);

typedef virJSONValuePtr (*virNetServerClientPrivPreExecRestart)(virNetServerClientPtr client,
                                                                void *data);
typedef void *(*virNetServerClientPrivNewPostExecRestart)(virNetServerClientPtr client,
                                                          virJSONValuePtr object,
                                                          void *opaque);
typedef void *(*virNetServerClientPrivNew)(virNetServerClientPtr client,
                                           void *opaque);

virNetServerClientPtr virNetServerClientNew(unsigned long long id,
                                            virNetSocketPtr sock,
                                            int auth,
                                            bool readonly,
                                            size_t nrequests_max,
# ifdef WITH_GNUTLS
                                            virNetTLSContextPtr tls,
# endif
                                            virNetServerClientPrivNew privNew,
                                            virNetServerClientPrivPreExecRestart privPreExecRestart,
                                            virFreeCallback privFree,
                                            void *privOpaque);

virNetServerClientPtr virNetServerClientNewPostExecRestart(virJSONValuePtr object,
                                                           virNetServerClientPrivNewPostExecRestart privNew,
                                                           virNetServerClientPrivPreExecRestart privPreExecRestart,
                                                           virFreeCallback privFree,
                                                           void *privOpaque,
                                                           void *opaque);

virJSONValuePtr virNetServerClientPreExecRestart(virNetServerClientPtr client);

int virNetServerClientAddFilter(virNetServerClientPtr client,
                                virNetServerClientFilterFunc func,
                                void *opaque);

void virNetServerClientRemoveFilter(virNetServerClientPtr client,
                                    int filterID);

int virNetServerClientGetAuth(virNetServerClientPtr client);
void virNetServerClientSetAuth(virNetServerClientPtr client, int auth);
bool virNetServerClientGetReadonly(virNetServerClientPtr client);
unsigned long long virNetServerClientGetID(virNetServerClientPtr client);
long long virNetServerClientGetTimestamp(virNetServerClientPtr client);

# ifdef WITH_GNUTLS
bool virNetServerClientHasTLSSession(virNetServerClientPtr client);
virNetTLSSessionPtr virNetServerClientGetTLSSession(virNetServerClientPtr client);
int virNetServerClientGetTLSKeySize(virNetServerClientPtr client);
# endif

# ifdef WITH_SASL
bool virNetServerClientHasSASLSession(virNetServerClientPtr client);
void virNetServerClientSetSASLSession(virNetServerClientPtr client,
                                      virNetSASLSessionPtr sasl);
virNetSASLSessionPtr virNetServerClientGetSASLSession(virNetServerClientPtr client);
# endif

int virNetServerClientGetFD(virNetServerClientPtr client);

bool virNetServerClientIsSecure(virNetServerClientPtr client);

bool virNetServerClientIsLocal(virNetServerClientPtr client);

int virNetServerClientGetUNIXIdentity(virNetServerClientPtr client,
                                      uid_t *uid, gid_t *gid, pid_t *pid,
                                      unsigned long long *timestamp);

int virNetServerClientGetSELinuxContext(virNetServerClientPtr client,
                                        char **context);

virIdentityPtr virNetServerClientGetIdentity(virNetServerClientPtr client);

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

const char *virNetServerClientLocalAddrStringSASL(virNetServerClientPtr client);
const char *virNetServerClientRemoteAddrStringSASL(virNetServerClientPtr client);
const char *virNetServerClientRemoteAddrStringURI(virNetServerClientPtr client);

int virNetServerClientSendMessage(virNetServerClientPtr client,
                                  virNetMessagePtr msg);

bool virNetServerClientNeedAuth(virNetServerClientPtr client);

int virNetServerClientGetTransport(virNetServerClientPtr client);
int virNetServerClientGetInfo(virNetServerClientPtr client,
                              bool *readonly, char **sock_addr,
                              virIdentityPtr *identity);

void virNetServerClientSetQuietEOF(virNetServerClientPtr client);

#endif /* __VIR_NET_SERVER_CLIENT_H__ */
