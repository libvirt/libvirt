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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_NET_CLIENT_H__
# define __VIR_NET_CLIENT_H__

# ifdef WITH_GNUTLS
#  include "virnettlscontext.h"
# endif
# include "virnetmessage.h"
# ifdef WITH_SASL
#  include "virnetsaslcontext.h"
# endif
# include "virnetclientprogram.h"
# include "virnetclientstream.h"
# include "virobject.h"
# include "viruri.h"


virNetClientPtr virNetClientNewUNIX(const char *path,
                                    bool spawnDaemon,
                                    const char *binary);

virNetClientPtr virNetClientNewTCP(const char *nodename,
                                   const char *service,
                                   int family);

virNetClientPtr virNetClientNewSSH(const char *nodename,
                                   const char *service,
                                   const char *binary,
                                   const char *username,
                                   bool noTTY,
                                   bool noVerify,
                                   const char *netcat,
                                   const char *keyfile,
                                   const char *path);

virNetClientPtr virNetClientNewLibSSH2(const char *host,
                                       const char *port,
                                       int family,
                                       const char *username,
                                       const char *privkeyPath,
                                       const char *knownHostsPath,
                                       const char *knownHostsVerify,
                                       const char *authMethods,
                                       const char *netcatPath,
                                       const char *socketPath,
                                       virConnectAuthPtr authPtr,
                                       virURIPtr uri);

virNetClientPtr virNetClientNewExternal(const char **cmdargv);

int virNetClientRegisterAsyncIO(virNetClientPtr client);
int virNetClientRegisterKeepAlive(virNetClientPtr client);

typedef void (*virNetClientCloseFunc)(virNetClientPtr client,
                                      int reason,
                                      void *opaque);

void virNetClientSetCloseCallback(virNetClientPtr client,
                                  virNetClientCloseFunc cb,
                                  void *opaque,
                                  virFreeCallback ff);

int virNetClientGetFD(virNetClientPtr client);
int virNetClientDupFD(virNetClientPtr client, bool cloexec);

bool virNetClientHasPassFD(virNetClientPtr client);

int virNetClientAddProgram(virNetClientPtr client,
                           virNetClientProgramPtr prog);

int virNetClientAddStream(virNetClientPtr client,
                          virNetClientStreamPtr st);

void virNetClientRemoveStream(virNetClientPtr client,
                              virNetClientStreamPtr st);

int virNetClientSendWithReply(virNetClientPtr client,
                              virNetMessagePtr msg);

int virNetClientSendNoReply(virNetClientPtr client,
                            virNetMessagePtr msg);

int virNetClientSendNonBlock(virNetClientPtr client,
                             virNetMessagePtr msg);

int virNetClientSendWithReplyStream(virNetClientPtr client,
                                    virNetMessagePtr msg,
                                    virNetClientStreamPtr st);

# ifdef WITH_SASL
void virNetClientSetSASLSession(virNetClientPtr client,
                                virNetSASLSessionPtr sasl);
# endif

# ifdef WITH_GNUTLS
int virNetClientSetTLSSession(virNetClientPtr client,
                              virNetTLSContextPtr tls);
# endif

bool virNetClientIsEncrypted(virNetClientPtr client);
bool virNetClientIsOpen(virNetClientPtr client);

const char *virNetClientLocalAddrString(virNetClientPtr client);
const char *virNetClientRemoteAddrString(virNetClientPtr client);

# ifdef WITH_GNUTLS
int virNetClientGetTLSKeySize(virNetClientPtr client);
# endif

void virNetClientClose(virNetClientPtr client);

bool virNetClientKeepAliveIsSupported(virNetClientPtr client);
int virNetClientKeepAliveStart(virNetClientPtr client,
                               int interval,
                               unsigned int count);

void virNetClientKeepAliveStop(virNetClientPtr client);

#endif /* __VIR_NET_CLIENT_H__ */
