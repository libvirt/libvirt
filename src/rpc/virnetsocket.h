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
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "virsocketaddr.h"
#include "vircommand.h"
#include "virnettlscontext.h"
#include "virobject.h"
#ifdef WITH_SASL
# include "virnetsaslcontext.h"
#endif
#include "virjson.h"
#include "viruri.h"

typedef struct _virNetSocket virNetSocket;

G_DEFINE_AUTOPTR_CLEANUP_FUNC(virNetSocket, virObjectUnref);

typedef void (*virNetSocketIOFunc)(virNetSocket *sock,
                                   int events,
                                   void *opaque);


int virNetSocketCheckProtocols(bool *hasIPv4,
                               bool *hasIPv6);

int virNetSocketNewListenTCP(const char *nodename,
                             const char *service,
                             int family,
                             virNetSocket ***addrs,
                             size_t *naddrs);

int virNetSocketNewListenUNIX(const char *path,
                              mode_t mask,
                              uid_t user,
                              gid_t grp,
                              virNetSocket **addr);

int virNetSocketNewListenFD(int fd,
                            bool unlinkUNIX,
                            virNetSocket **addr);

int virNetSocketNewConnectTCP(const char *nodename,
                              const char *service,
                              int family,
                              virNetSocket **addr);

int virNetSocketNewConnectUNIX(const char *path,
                               const char *spawnDaemonPath,
                               virNetSocket **addr);

int virNetSocketNewConnectCommand(virCommand *cmd,
                                  virNetSocket **retsock);

int virNetSocketNewConnectSSH(const char *nodename,
                              const char *service,
                              const char *binary,
                              const char *username,
                              bool noTTY,
                              bool noVerify,
                              const char *keyfile,
                              const char *command,
                              virNetSocket **addr);

int virNetSocketNewConnectLibSSH2(const char *host,
                                  const char *port,
                                  int family,
                                  const char *username,
                                  const char *privkey,
                                  const char *knownHosts,
                                  const char *knownHostsVerify,
                                  const char *authMethods,
                                  const char *command,
                                  virConnectAuthPtr auth,
                                  virURI *uri,
                                  virNetSocket **retsock);

int virNetSocketNewConnectLibssh(const char *host,
                                 const char *port,
                                 int family,
                                 const char *username,
                                 const char *privkey,
                                 const char *knownHosts,
                                 const char *knownHostsVerify,
                                 const char *authMethods,
                                 const char *command,
                                 virConnectAuthPtr auth,
                                 virURI *uri,
                                 virNetSocket **retsock);

int virNetSocketNewConnectExternal(const char **cmdargv,
                                   virNetSocket **addr);

int virNetSocketNewConnectSockFD(int sockfd,
                                 virNetSocket **retsock);

virNetSocket *virNetSocketNewPostExecRestart(virJSONValue *object);

virJSONValue *virNetSocketPreExecRestart(virNetSocket *sock);

int virNetSocketGetFD(virNetSocket *sock);
int virNetSocketDupFD(virNetSocket *sock, bool cloexec);

bool virNetSocketIsLocal(virNetSocket *sock);

bool virNetSocketHasPassFD(virNetSocket *sock);

char *virNetSocketGetPath(virNetSocket *sock);
int virNetSocketGetPort(virNetSocket *sock);

int virNetSocketGetUNIXIdentity(virNetSocket *sock,
                                uid_t *uid,
                                gid_t *gid,
                                pid_t *pid,
                                unsigned long long *timestamp)
    G_NO_INLINE;
int virNetSocketGetSELinuxContext(virNetSocket *sock,
                                  char **context)
    G_NO_INLINE;

int virNetSocketSetBlocking(virNetSocket *sock,
                            bool blocking);

void virNetSocketSetQuietEOF(virNetSocket *sock);

ssize_t virNetSocketRead(virNetSocket *sock, char *buf, size_t len);
ssize_t virNetSocketWrite(virNetSocket *sock, const char *buf, size_t len);

int virNetSocketSendFD(virNetSocket *sock, int fd);
int virNetSocketRecvFD(virNetSocket *sock, int *fd);

void virNetSocketSetTLSSession(virNetSocket *sock,
                               virNetTLSSession *sess);

#ifdef WITH_SASL
void virNetSocketSetSASLSession(virNetSocket *sock,
                                virNetSASLSession *sess);
#endif
bool virNetSocketHasCachedData(virNetSocket *sock);
bool virNetSocketHasPendingData(virNetSocket *sock);

const char *virNetSocketLocalAddrStringSASL(virNetSocket *sock);
const char *virNetSocketRemoteAddrStringSASL(virNetSocket *sock);
const char *virNetSocketRemoteAddrStringURI(virNetSocket *sock);

int virNetSocketListen(virNetSocket *sock, int backlog);
int virNetSocketAccept(virNetSocket *sock,
                       virNetSocket **clientsock);

int virNetSocketAddIOCallback(virNetSocket *sock,
                              int events,
                              virNetSocketIOFunc func,
                              void *opaque,
                              virFreeCallback ff);

void virNetSocketUpdateIOCallback(virNetSocket *sock,
                                  int events);

void virNetSocketRemoveIOCallback(virNetSocket *sock);

void virNetSocketClose(virNetSocket *sock);
