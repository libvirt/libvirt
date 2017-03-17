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
 *
 * Author: Daniel P. Berrange <berrange@redhat.com>
 */

#ifndef __VIR_NET_SOCKET_H__
# define __VIR_NET_SOCKET_H__

# include "virsocketaddr.h"
# include "vircommand.h"
# ifdef WITH_GNUTLS
#  include "virnettlscontext.h"
# endif
# include "virobject.h"
# ifdef WITH_SASL
#  include "virnetsaslcontext.h"
# endif
# include "virjson.h"
# include "viruri.h"

typedef struct _virNetSocket virNetSocket;
typedef virNetSocket *virNetSocketPtr;


typedef void (*virNetSocketIOFunc)(virNetSocketPtr sock,
                                   int events,
                                   void *opaque);


int virNetSocketCheckProtocols(bool *hasIPv4,
                               bool *hasIPv6);

int virNetSocketNewListenTCP(const char *nodename,
                             const char *service,
                             int family,
                             virNetSocketPtr **addrs,
                             size_t *naddrs);

int virNetSocketNewListenUNIX(const char *path,
                              mode_t mask,
                              uid_t user,
                              gid_t grp,
                              virNetSocketPtr *addr);

int virNetSocketNewListenFD(int fd,
                            virNetSocketPtr *addr);

int virNetSocketNewConnectTCP(const char *nodename,
                              const char *service,
                              int family,
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
                                  virURIPtr uri,
                                  virNetSocketPtr *retsock);

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
                                 virURIPtr uri,
                                 virNetSocketPtr *retsock);

int virNetSocketNewConnectExternal(const char **cmdargv,
                                   virNetSocketPtr *addr);

int virNetSocketNewConnectSockFD(int sockfd,
                                 virNetSocketPtr *retsock);

virNetSocketPtr virNetSocketNewPostExecRestart(virJSONValuePtr object);

virJSONValuePtr virNetSocketPreExecRestart(virNetSocketPtr sock);

int virNetSocketGetFD(virNetSocketPtr sock);
int virNetSocketDupFD(virNetSocketPtr sock, bool cloexec);

bool virNetSocketIsLocal(virNetSocketPtr sock);

bool virNetSocketHasPassFD(virNetSocketPtr sock);

int virNetSocketGetPort(virNetSocketPtr sock);

int virNetSocketGetUNIXIdentity(virNetSocketPtr sock,
                                uid_t *uid,
                                gid_t *gid,
                                pid_t *pid,
                                unsigned long long *timestamp);
int virNetSocketGetSELinuxContext(virNetSocketPtr sock,
                                  char **context);

int virNetSocketSetBlocking(virNetSocketPtr sock,
                            bool blocking);

void virNetSocketSetQuietEOF(virNetSocketPtr sock);

ssize_t virNetSocketRead(virNetSocketPtr sock, char *buf, size_t len);
ssize_t virNetSocketWrite(virNetSocketPtr sock, const char *buf, size_t len);

int virNetSocketSendFD(virNetSocketPtr sock, int fd);
int virNetSocketRecvFD(virNetSocketPtr sock, int *fd);

# ifdef WITH_GNUTLS
void virNetSocketSetTLSSession(virNetSocketPtr sock,
                               virNetTLSSessionPtr sess);
# endif

# ifdef WITH_SASL
void virNetSocketSetSASLSession(virNetSocketPtr sock,
                                virNetSASLSessionPtr sess);
# endif
bool virNetSocketHasCachedData(virNetSocketPtr sock);
bool virNetSocketHasPendingData(virNetSocketPtr sock);

const char *virNetSocketLocalAddrStringSASL(virNetSocketPtr sock);
const char *virNetSocketRemoteAddrStringSASL(virNetSocketPtr sock);
const char *virNetSocketRemoteAddrStringURI(virNetSocketPtr sock);

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
