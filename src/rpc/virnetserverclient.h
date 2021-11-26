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
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virNetServer, virObjectUnref);

typedef struct _virNetServerClient virNetServerClient;
G_DEFINE_AUTOPTR_CLEANUP_FUNC(virNetServerClient, virObjectUnref);

/* This function owns the "msg" pointer it is passed and
 * must arrange for virNetMessageFree to be called on it
 */
typedef void (*virNetServerClientDispatchFunc)(virNetServerClient *client,
                                               virNetMessage *msg,
                                               void *opaque);

/*
 * @client is locked when this callback is called
 */
typedef int (*virNetServerClientFilterFunc)(virNetServerClient *client,
                                            virNetMessage *msg,
                                            void *opaque);

/*
 * @data: value allocated by virNetServerClintPrivNew(PostExecRestart) callback
 */
typedef virJSONValue *(*virNetServerClientPrivPreExecRestart)(virNetServerClient *client,
                                                                void *data);
/*
 * @opaque: value of @privOpaque from virNetServerClientNewPostExecRestart
 */
typedef void *(*virNetServerClientPrivNewPostExecRestart)(virNetServerClient *client,
                                                          virJSONValue *object,
                                                          void *opaque);
/*
 * @opaque: value of @privOpaque from virNetServerClientNew
 */
typedef void *(*virNetServerClientPrivNew)(virNetServerClient *client,
                                           void *opaque);

virNetServerClient *virNetServerClientNew(unsigned long long id,
                                            virNetSocket *sock,
                                            int auth,
                                            bool readonly,
                                            size_t nrequests_max,
                                            virNetTLSContext *tls,
                                            virNetServerClientPrivNew privNew,
                                            virNetServerClientPrivPreExecRestart privPreExecRestart,
                                            virFreeCallback privFree,
                                            void *privOpaque)
    ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(7) ATTRIBUTE_NONNULL(9);

virNetServerClient *virNetServerClientNewPostExecRestart(virNetServer *srv,
                                                           virJSONValue *object,
                                                           virNetServerClientPrivNewPostExecRestart privNew,
                                                           virNetServerClientPrivPreExecRestart privPreExecRestart,
                                                           virFreeCallback privFree,
                                                           void *privOpaque)
    ATTRIBUTE_NONNULL(1) ATTRIBUTE_NONNULL(2) ATTRIBUTE_NONNULL(3)
    ATTRIBUTE_NONNULL(4) ATTRIBUTE_NONNULL(5);

virJSONValue *virNetServerClientPreExecRestart(virNetServerClient *client);

int virNetServerClientAddFilter(virNetServerClient *client,
                                virNetServerClientFilterFunc func,
                                void *opaque);

void virNetServerClientRemoveFilter(virNetServerClient *client,
                                    int filterID);

int virNetServerClientGetAuth(virNetServerClient *client);
void virNetServerClientSetAuthLocked(virNetServerClient *client, int auth);
bool virNetServerClientGetReadonly(virNetServerClient *client);
void virNetServerClientSetReadonly(virNetServerClient *client, bool readonly);
unsigned long long virNetServerClientGetID(virNetServerClient *client);
long long virNetServerClientGetTimestamp(virNetServerClient *client);

bool virNetServerClientHasTLSSession(virNetServerClient *client);
virNetTLSSession *virNetServerClientGetTLSSession(virNetServerClient *client);
int virNetServerClientGetTLSKeySize(virNetServerClient *client);

#ifdef WITH_SASL
bool virNetServerClientHasSASLSession(virNetServerClient *client);
void virNetServerClientSetSASLSession(virNetServerClient *client,
                                      virNetSASLSession *sasl);
virNetSASLSession *virNetServerClientGetSASLSession(virNetServerClient *client);
#endif

int virNetServerClientGetFD(virNetServerClient *client);

bool virNetServerClientIsSecure(virNetServerClient *client);

bool virNetServerClientIsLocal(virNetServerClient *client);

int virNetServerClientGetUNIXIdentity(virNetServerClient *client,
                                      uid_t *uid, gid_t *gid, pid_t *pid,
                                      unsigned long long *timestamp);

int virNetServerClientGetSELinuxContext(virNetServerClient *client,
                                        char **context);

virIdentity *virNetServerClientGetIdentity(virNetServerClient *client);
void virNetServerClientSetIdentity(virNetServerClient *client,
                                   virIdentity *identity);

void *virNetServerClientGetPrivateData(virNetServerClient *client);

typedef void (*virNetServerClientCloseFunc)(virNetServerClient *client);

void virNetServerClientSetCloseHook(virNetServerClient *client,
                                    virNetServerClientCloseFunc cf);

void virNetServerClientSetDispatcher(virNetServerClient *client,
                                     virNetServerClientDispatchFunc func,
                                     void *opaque);
void virNetServerClientClose(virNetServerClient *client);
void virNetServerClientCloseLocked(virNetServerClient *client);
bool virNetServerClientIsClosedLocked(virNetServerClient *client);

void virNetServerClientDelayedClose(virNetServerClient *client);
void virNetServerClientImmediateClose(virNetServerClient *client);
bool virNetServerClientWantCloseLocked(virNetServerClient *client);

int virNetServerClientInit(virNetServerClient *client);

int virNetServerClientInitKeepAlive(virNetServerClient *client,
                                    int interval,
                                    unsigned int count);
bool virNetServerClientCheckKeepAlive(virNetServerClient *client,
                                      virNetMessage *msg);
int virNetServerClientStartKeepAlive(virNetServerClient *client);

const char *virNetServerClientLocalAddrStringSASL(virNetServerClient *client);
const char *virNetServerClientRemoteAddrStringSASL(virNetServerClient *client);
const char *virNetServerClientRemoteAddrStringURI(virNetServerClient *client);

int virNetServerClientSendMessage(virNetServerClient *client,
                                  virNetMessage *msg);

bool virNetServerClientIsAuthenticated(virNetServerClient *client);
bool virNetServerClientIsAuthPendingLocked(virNetServerClient *client);
void virNetServerClientSetAuthPendingLocked(virNetServerClient *client, bool auth_pending);

int virNetServerClientGetTransport(virNetServerClient *client);
int virNetServerClientGetInfo(virNetServerClient *client,
                              bool *readonly, char **sock_addr,
                              virIdentity **identity);

void virNetServerClientSetQuietEOF(virNetServerClient *client);
