/*
 * virnetclient.h: generic network RPC client
 *
 * Copyright (C) 2006-2011 Red Hat, Inc.
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

#ifndef __VIR_NET_CLIENT_H__
# define __VIR_NET_CLIENT_H__

# include "virnettlscontext.h"
# include "virnetmessage.h"
# ifdef HAVE_SASL
#  include "virnetsaslcontext.h"
# endif
# include "virnetclientprogram.h"
# include "virnetclientstream.h"


virNetClientPtr virNetClientNewUNIX(const char *path,
                                    bool spawnDaemon,
                                    const char *daemon);

virNetClientPtr virNetClientNewTCP(const char *nodename,
                                   const char *service);

virNetClientPtr virNetClientNewSSH(const char *nodename,
                                   const char *service,
                                   const char *binary,
                                   const char *username,
                                   bool noTTY,
                                   bool noVerify,
                                   const char *netcat,
                                   const char *keyfile,
                                   const char *path);

virNetClientPtr virNetClientNewExternal(const char **cmdargv);

void virNetClientRef(virNetClientPtr client);

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

# ifdef HAVE_SASL
void virNetClientSetSASLSession(virNetClientPtr client,
                                virNetSASLSessionPtr sasl);
# endif

int virNetClientSetTLSSession(virNetClientPtr client,
                              virNetTLSContextPtr tls);

bool virNetClientIsEncrypted(virNetClientPtr client);
bool virNetClientIsOpen(virNetClientPtr client);

const char *virNetClientLocalAddrString(virNetClientPtr client);
const char *virNetClientRemoteAddrString(virNetClientPtr client);

int virNetClientGetTLSKeySize(virNetClientPtr client);

void virNetClientFree(virNetClientPtr client);
void virNetClientClose(virNetClientPtr client);

bool virNetClientKeepAliveIsSupported(virNetClientPtr client);
int virNetClientKeepAliveStart(virNetClientPtr client,
                               int interval,
                               unsigned int count);

#endif /* __VIR_NET_CLIENT_H__ */
