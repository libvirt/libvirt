/*
 * virnetsocket.h: generic network socket handling
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

#ifndef __VIR_NET_SOCKET_H__
# define __VIR_NET_SOCKET_H__

# include "virsocketaddr.h"
# include "command.h"
# include "virnettlscontext.h"
# ifdef HAVE_SASL
#  include "virnetsaslcontext.h"
# endif

typedef struct _virNetSocket virNetSocket;
typedef virNetSocket *virNetSocketPtr;


typedef void (*virNetSocketIOFunc)(virNetSocketPtr sock,
                                   int events,
                                   void *opaque);


int virNetSocketNewListenTCP(const char *nodename,
                             const char *service,
                             virNetSocketPtr **addrs,
                             size_t *naddrs);

int virNetSocketNewListenUNIX(const char *path,
                              mode_t mask,
                              uid_t user,
                              gid_t grp,
                              virNetSocketPtr *addr);

int virNetSocketNewConnectTCP(const char *nodename,
                              const char *service,
                              virNetSocketPtr *addr);

int virNetSocketNewConnectUNIX(const char *path,
                               bool spawnDaemon,
                               const char *binary,
                               virNetSocketPtr *addr);

int virNetSocketNewConnectCommand(virCommandPtr cmd,
                                  virNetSocketPtr *retsock);

int virNetSocketNewConnectSSH(const char *nodename,
                              const char *service,
                              const char *binary,
                              const char *username,
                              bool noTTY,
                              bool noVerify,
                              const char *netcat,
                              const char *keyfile,
                              const char *path,
                              virNetSocketPtr *addr);

int virNetSocketNewConnectExternal(const char **cmdargv,
                                   virNetSocketPtr *addr);

int virNetSocketGetFD(virNetSocketPtr sock);
int virNetSocketDupFD(virNetSocketPtr sock, bool cloexec);

bool virNetSocketIsLocal(virNetSocketPtr sock);

bool virNetSocketHasPassFD(virNetSocketPtr sock);

int virNetSocketGetPort(virNetSocketPtr sock);

int virNetSocketGetUNIXIdentity(virNetSocketPtr sock,
                                uid_t *uid,
                                gid_t *gid,
                                pid_t *pid);

int virNetSocketSetBlocking(virNetSocketPtr sock,
                            bool blocking);

ssize_t virNetSocketRead(virNetSocketPtr sock, char *buf, size_t len);
ssize_t virNetSocketWrite(virNetSocketPtr sock, const char *buf, size_t len);

int virNetSocketSendFD(virNetSocketPtr sock, int fd);
int virNetSocketRecvFD(virNetSocketPtr sock, int *fd);

void virNetSocketSetTLSSession(virNetSocketPtr sock,
                               virNetTLSSessionPtr sess);
# ifdef HAVE_SASL
void virNetSocketSetSASLSession(virNetSocketPtr sock,
                                virNetSASLSessionPtr sess);
# endif
bool virNetSocketHasCachedData(virNetSocketPtr sock);
bool virNetSocketHasPendingData(virNetSocketPtr sock);
void virNetSocketRef(virNetSocketPtr sock);
void virNetSocketFree(virNetSocketPtr sock);

const char *virNetSocketLocalAddrString(virNetSocketPtr sock);
const char *virNetSocketRemoteAddrString(virNetSocketPtr sock);

int virNetSocketListen(virNetSocketPtr sock, int backlog);
int virNetSocketAccept(virNetSocketPtr sock,
                       virNetSocketPtr *clientsock);

int virNetSocketAddIOCallback(virNetSocketPtr sock,
                              int events,
                              virNetSocketIOFunc func,
                              void *opaque,
                              virFreeCallback ff);

void virNetSocketUpdateIOCallback(virNetSocketPtr sock,
                                  int events);

void virNetSocketRemoveIOCallback(virNetSocketPtr sock);

void virNetSocketClose(virNetSocketPtr sock);


#endif /* __VIR_NET_SOCKET_H__ */
