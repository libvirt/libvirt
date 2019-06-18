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
 */

#pragma once

#include "viridentity.h"
#include "virnetsocket.h"
#include "virnetmessage.h"
#include "virobject.h"
#include "virjson.h"

typedef struct _virNetServer virNetServer;
typedef virNetServer *virNetServerPtr;

typedef struct _virNetServerClient virNetServerClient;
typedef virNetServerClient *virNetServerClientPtr;

/* This function owns the "msg" pointer it is passed and
 * must arrange for virNetMessageFree to be called on it
 */
typedef void (*virNetServerClientDispatchFunc)(virNetServerClientPtr client,
                                               virNetMessagePtr msg,
                                               void *opaque);

typedef int (*virNetServerClientFilterFunc)(virNetServerClientPtr client,
                                            virNetMessagePtr msg,
                                            void *opaque);

/*
 * @data: value allocated by virNetServerClintPrivNew(PostExecRestart) callback
 */
typedef virJSONValuePtr (*virNetServerClientPrivPreExecRestart)(virNetServerClientPtr client,
                                                                void *data);
/*
 * @opaque: value of @privOpaque from virNetServerClientNewPostExecRestart
 */
typedef void *(*virNetServerClientPrivNewPostExecRestart)(virNetServerClientPtr client,
                                                          virJSONValuePtr object,
                                                          void *opaque);
/*
 * @opaque: value of @privOpaque from virNetServerClientNew
 */
typedef void *(*virNetServerClientPrivNew)(virNetServerClientPtr client,
                                           void *opaque);

virNetServerClientPtr virNetServerClientNew(unsigned long long id,
                                            virNetSocketPtr sock,
                                            int auth,
                                            bool readonly,
                                            size_t nrequests_max,
                                            virNetTLSContextPtr tls,
                                            virNetServerClientPrivNew privNew,
                                            virNetServerClientPrivPreExecRestart privPreExecRestart,
                                            virFreeCallback privFree,
                                            void *privOpaque)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(7) ATTRIBUTE_NONNULL(9);

virNetServerClientPtr virNetServerClientNewPostExecRestart(virNetServerPtr srv,
                                                           virJSONValuePtr object,
                                                           virNetServerClientPrivNewPostExecRestart privNew,
                                                           virNetServerClientPrivPreExecRestart privPreExecRestart,
                                                           virFreeCallback privFree,
                                                           void *privOpaque)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5);

virJSONValuePtr virNetServerClientPreExecRestart(virNetServerClientPtr client);

int virNetServerClientAddFilter(virNetServerClientPtr client,
                                virNetServerClientFilterFunc func,
                                void *opaque);

void virNetServerClientRemoveFilter(virNetServerClientPtr client,
                                    int filterID);

int virNetServerClientGetAuth(virNetServerClientPtr client);
void virNetServerClientSetAuthLocked(virNetServerClientPtr client, int auth);
bool virNetServerClientGetReadonly(virNetServerClientPtr client);
void virNetServerClientSetReadonly(virNetServerClientPtr client, bool readonly);
unsigned long long virNetServerClientGetID(virNetServerClientPtr client);
long long virNetServerClientGetTimestamp(virNetServerClientPtr client);

bool virNetServerClientHasTLSSession(virNetServerClientPtr client);
virNetTLSSessionPtr virNetServerClientGetTLSSession(virNetServerClientPtr client);
int virNetServerClientGetTLSKeySize(virNetServerClientPtr client);

#ifdef WITH_SASL
bool virNetServerClientHasSASLSession(virNetServerClientPtr client);
void virNetServerClientSetSASLSession(virNetServerClientPtr client,
                                      virNetSASLSessionPtr sasl);
virNetSASLSessionPtr virNetServerClientGetSASLSession(virNetServerClientPtr client);
#endif

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
void virNetServerClientCloseLocked(virNetServerClientPtr client);
bool virNetServerClientIsClosedLocked(virNetServerClientPtr client);

void virNetServerClientDelayedClose(virNetServerClientPtr client);
void virNetServerClientImmediateClose(virNetServerClientPtr client);
bool virNetServerClientWantCloseLocked(virNetServerClientPtr client);

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

bool virNetServerClientIsAuthenticated(virNetServerClientPtr client);
bool virNetServerClientIsAuthPendingLocked(virNetServerClientPtr client);
void virNetServerClientSetAuthPendingLocked(virNetServerClientPtr client, bool auth_pending);

int virNetServerClientGetTransport(virNetServerClientPtr client);
int virNetServerClientGetInfo(virNetServerClientPtr client,
                              bool *readonly, char **sock_addr,
                              virIdentityPtr *identity);

void virNetServerClientSetQuietEOF(virNetServerClientPtr client);
