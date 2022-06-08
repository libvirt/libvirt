/*
 * virnetclient.h: generic network RPC client
 *
 * Copyright (C) 2006-2012 Red Hat, Inc.
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

#include "virnettlscontext.h"
#include "virnetmessage.h"
#ifdef WITH_SASL
# include "virnetsaslcontext.h"
#endif
#include "virnetclientprogram.h"
#include "virnetclientstream.h"
#include "viruri.h"

typedef enum {
    VIR_NET_CLIENT_PROXY_AUTO,
    VIR_NET_CLIENT_PROXY_NETCAT,
    VIR_NET_CLIENT_PROXY_NATIVE,

    VIR_NET_CLIENT_PROXY_LAST,
} virNetClientProxy;

VIR_ENUM_DECL(virNetClientProxy);

char *
virNetClientSSHHelperCommand(virNetClientProxy proxy,
                             const char *netcatPath,
                             const char *socketPath,
                             const char *driverURI,
                             bool readonly);

virNetClient *virNetClientNewUNIX(const char *path,
                                  const char *spawnDaemonPath);

virNetClient *virNetClientNewTCP(const char *nodename,
                                   const char *service,
                                   int family);

virNetClient *virNetClientNewSSH(const char *nodename,
                                   const char *service,
                                   const char *binary,
                                   const char *username,
                                   bool noTTY,
                                   bool noVerify,
                                   const char *keyfile,
                                   virNetClientProxy proxy,
                                   const char *netcatPath,
                                   const char *socketPath,
                                   const char *driverURI,
                                   bool readonly);

virNetClient *virNetClientNewLibSSH2(const char *host,
                                       const char *port,
                                       int family,
                                       const char *username,
                                       const char *privkeyPath,
                                       const char *knownHostsPath,
                                       const char *knownHostsVerify,
                                       const char *authMethods,
                                       virNetClientProxy proxy,
                                       const char *netcatPath,
                                       const char *socketPath,
                                       const char *driverURI,
                                       bool readonly,
                                       virConnectAuthPtr authPtr,
                                       virURI *uri);

virNetClient *virNetClientNewLibssh(const char *host,
                                      const char *port,
                                      int family,
                                      const char *username,
                                      const char *privkeyPath,
                                      const char *knownHostsPath,
                                      const char *knownHostsVerify,
                                      const char *authMethods,
                                      virNetClientProxy proxy,
                                      const char *netcatPath,
                                      const char *socketPath,
                                      const char *driverURI,
                                      bool readonly,
                                      virConnectAuthPtr authPtr,
                                      virURI *uri);

virNetClient *virNetClientNewExternal(const char **cmdargv);

int virNetClientRegisterAsyncIO(virNetClient *client);
int virNetClientRegisterKeepAlive(virNetClient *client);

typedef void (*virNetClientCloseFunc)(virNetClient *client,
                                      int reason,
                                      void *opaque);

void virNetClientSetCloseCallback(virNetClient *client,
                                  virNetClientCloseFunc cb,
                                  void *opaque,
                                  virFreeCallback ff);

int virNetClientGetFD(virNetClient *client);
int virNetClientDupFD(virNetClient *client, bool cloexec);

bool virNetClientHasPassFD(virNetClient *client);

int virNetClientAddProgram(virNetClient *client,
                           virNetClientProgram *prog);

int virNetClientAddStream(virNetClient *client,
                          virNetClientStream *st);

void virNetClientRemoveStream(virNetClient *client,
                              virNetClientStream *st);

int virNetClientSendWithReply(virNetClient *client,
                              virNetMessage *msg);

int virNetClientSendNonBlock(virNetClient *client,
                             virNetMessage *msg);

int virNetClientSendStream(virNetClient *client,
                           virNetMessage *msg,
                           virNetClientStream *st);

#ifdef WITH_SASL
void virNetClientSetSASLSession(virNetClient *client,
                                virNetSASLSession *sasl);
#endif

int virNetClientSetTLSSession(virNetClient *client,
                              virNetTLSContext *tls);

bool virNetClientIsEncrypted(virNetClient *client);
bool virNetClientIsOpen(virNetClient *client);

const char *virNetClientLocalAddrStringSASL(virNetClient *client);
const char *virNetClientRemoteAddrStringSASL(virNetClient *client);

int virNetClientGetTLSKeySize(virNetClient *client);

void virNetClientClose(virNetClient *client);

bool virNetClientKeepAliveIsSupported(virNetClient *client);
int virNetClientKeepAliveStart(virNetClient *client,
                               int interval,
                               unsigned int count);

void virNetClientKeepAliveStop(virNetClient *client);
